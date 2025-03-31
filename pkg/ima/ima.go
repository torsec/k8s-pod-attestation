package ima

import (
	"bytes"
	"crypto/sha1"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"regexp"
	"strings"
)

const containerRuntimeDependencies = "/usr/bin/containerd:/usr/bin/containerd:/usr/lib/systemd/systemd:swapper/0"
const ContainerRuntimeName = "/usr/bin/containerd-shim-runc-v2"
const containerRuntimeEngineId = "containerd"

const CgpathTemplateEntryFields = 7
const COLON_BYTE = byte(58) // ASCII code for ":"
const NULL_BYTE = byte(0)

// extractSHADigest extracts the algorithm (e.g., "sha256") and the actual hex digest from a string with the format "sha<algo>:<hex_digest>"
func extractShaDigest(input string) (string, string, error) {
	// Define a regular expression to match the prefix "sha<number>:" followed by the hex digest
	re := regexp.MustCompile(`^sha[0-9]+:`)

	// Check if the input matches the expected format
	if matches := re.FindStringSubmatch(input); matches != nil {
		fileHashElements := strings.Split(input, ":")

		return fileHashElements[0], fileHashElements[1], nil
	}
	return "", "", fmt.Errorf("input does not have a valid sha<algo>:<hex_digest> format")
}

// Helper function to compute the new hash by concatenating previous hash and template hash
func extendEntry(previousHash []byte, templateHash string) ([]byte, error) {
	// Create a new SHA context
	hash := sha256.New()

	// Decode the template hash from hexadecimal
	templateHashBytes, err := hex.DecodeString(templateHash)
	if err != nil {
		return nil, fmt.Errorf("failed to decode template hash field: %v", err)
	}

	// Concatenate previous hash and the new template hash
	dataToHash := append(previousHash, templateHashBytes...)

	// Compute the new hash
	hash.Write(dataToHash)
	return hash.Sum(nil), nil
}

// IMAVerification checks the integrity of the IMA measurement logger against the received Quote and returns the entries related to the pod being attested for statical analysis of executed software and the AttestationResult
func MeasurementLogValidation(imaMeasurementLog, pcr10Digest, podUid string) ([]model.IMAEntry, []model.IMAEntry, error) {
	isMeasurementLogValid := false

	decodedLog, err := base64.StdEncoding.DecodeString(imaMeasurementLog)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode IMA measurement logger: %v", err)
	}

	logLines := strings.Split(string(decodedLog), "\n")
	if len(logLines) > 0 && logLines[len(logLines)-1] == "" {
		logLines = logLines[:len(logLines)-1] // Remove the last empty line --> each entry adds a \n so last line will add an empty line
	}
	uniquePodEntries := make(map[string]model.IMAEntry)
	uniqueContainerRuntimeEntries := make(map[string]model.IMAEntry)

	// initial PCR configuration
	previousHash := make([]byte, 32)

	// Iterate through each line and extract relevant fields
	for idx, imaLine := range logLines {
		// Split the line by whitespace
		IMAFields := strings.Fields(imaLine)
		if len(IMAFields) < CgpathTemplateEntryFields {
			return nil, nil, fmt.Errorf("IMA measurement log integrity check failed: entry %d not compliant with template: %s", idx, imaLine)
		}

		templateHashField := IMAFields[1]
		depField := IMAFields[3]
		cgroupPathField := IMAFields[4]
		fileHashField := IMAFields[5]
		filePathField := IMAFields[6]

		hashAlgo, fileHash, err := extractShaDigest(fileHashField)
		if err != nil {
			return nil, nil, fmt.Errorf("IMA measurement log integrity check failed: entry: %d file hash is invalid: %s", idx, imaLine)
		}

		extendValue, err := validateEntry(templateHashField, depField, cgroupPathField, hashAlgo, fileHash, filePathField)
		if err != nil {
			return nil, nil, fmt.Errorf("IMA measurement log integrity check failed: entry: %d is invalid: %s", idx, imaLine)
		}

		// Use the helper function to extend ML cumulative hash with the newly computed template hash
		extendedHash, err := extendEntry(previousHash, extendValue)
		if err != nil {
			return nil, nil, fmt.Errorf("error computing hash at index %d: %v\n", idx, err)
		}

		// Update the previous hash for the next iteration
		previousHash = extendedHash
		if !isMeasurementLogValid && hex.EncodeToString(extendedHash) == pcr10Digest {
			isMeasurementLogValid = true
		}

		// check if entry belongs to container or is pure a host measurement, otherwise after having computed the extend hash, go to next entry in IMA ML
		if !strings.Contains(depField, containerRuntimeEngineId) {
			continue
		}

		// entry is host container-related not a pod entry
		if filePathField == ContainerRuntimeName || depField == containerRuntimeDependencies {
			// Create a unique key by combining filePath and fileHash
			entryKey := fmt.Sprintf("%s:%s", filePathField, fileHash)

			// Add the entry to the map if it doesn't exist
			if _, exists := uniqueContainerRuntimeEntries[entryKey]; !exists {
				uniqueContainerRuntimeEntries[entryKey] = model.IMAEntry{
					FilePath: filePathField,
					FileHash: fileHash,
				}
			}
			continue
		}

		// Check if the cgroup path contains the podUID
		if checkPodUidMatch(cgroupPathField, podUid) {

			// Create a unique key by combining filePath and fileHash
			entryKey := fmt.Sprintf("%s:%s", filePathField, fileHash)

			// Add the entry to the map if it doesn't exist
			if _, exists := uniquePodEntries[entryKey]; !exists {
				uniquePodEntries[entryKey] = model.IMAEntry{
					FilePath: filePathField,
					FileHash: fileHash,
				}
			}
		}
	}

	// Convert the final hash to a hex string for comparison
	cumulativeHashHex := hex.EncodeToString(previousHash)
	// Compare the computed hash with the provided PCR10Digest
	if cumulativeHashHex != pcr10Digest {
		return nil, nil, fmt.Errorf("IMA measurement log integrity check failed: computed hash does not match quote value")
	}

	// Convert the unique entries back to a slice
	podEntries := make([]model.IMAEntry, 0, len(uniquePodEntries))
	for _, entry := range uniquePodEntries {
		podEntries = append(podEntries, entry)
	}

	containerRuntimeEntries := make([]model.IMAEntry, 0, len(uniqueContainerRuntimeEntries))
	for _, entry := range uniqueContainerRuntimeEntries {
		containerRuntimeEntries = append(containerRuntimeEntries, entry)
	}

	// Return the collected IMA pod entries
	return podEntries, containerRuntimeEntries, nil
}

func checkPodUidMatch(path, podUid string) bool {
	var regexPattern string
	// Replace dashes in podUid with underscores
	adjustedPodUid := strings.ReplaceAll(podUid, "-", "_")
	// Regex pattern to match the pod UID in the path
	regexPattern = fmt.Sprintf(`kubepods[^\/]*-pod%s\.slice`, regexp.QuoteMeta(adjustedPodUid))

	// Compile the regex
	r, err := regexp.Compile(regexPattern)
	if err != nil {
		return false
	}
	// Check if the path contains the pod UID
	return r.MatchString(path)
}

func computeEntryTemplateHash(packedDep, packedCgroup, packedFileHash, packedFilePath []byte) (string, string) {
	packedTemplateEntry := append(packedDep, packedCgroup...)
	packedTemplateEntry = append(packedTemplateEntry, packedFileHash...)
	packedTemplateEntry = append(packedTemplateEntry, packedFilePath...)
	sha1Hash := sha1.Sum(packedTemplateEntry)
	sha256Hash := sha256.Sum256(packedTemplateEntry)

	return hex.EncodeToString(sha1Hash[:]), hex.EncodeToString(sha256Hash[:])
}

func packHashField(hashAlg string, fileHash []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Pack total length (algorithm + 2 extra bytes + hash length)
	totalLen := uint32(len(hashAlg) + 2 + len(fileHash))
	if err := binary.Write(buf, binary.LittleEndian, totalLen); err != nil {
		return nil, fmt.Errorf("failed to pack total length: %v", err)
	}

	// Pack algorithm
	if _, err := buf.Write([]byte(hashAlg)); err != nil {
		return nil, fmt.Errorf("failed to pack algorithm: %v", err)
	}

	// Pack COLON_BYTE (1 byte)
	if err := buf.WriteByte(COLON_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack COLON_BYTE: %v", err)
	}

	// Pack NULL_BYTE (1 byte)
	if err := buf.WriteByte(NULL_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack NULL_BYTE: %v", err)
	}

	// Pack fileHash (len(fileHash) bytes)
	if _, err := buf.Write(fileHash); err != nil {
		return nil, fmt.Errorf("failed to pack fileHash: %v", err)
	}

	return buf.Bytes(), nil
}

func packPathField(path []byte) ([]byte, error) {
	buf := new(bytes.Buffer)

	// Pack length (4 bytes)
	length := uint32(len(path) + 1) // length + 1 for NULL_BYTE
	if err := binary.Write(buf, binary.LittleEndian, length); err != nil {
		return nil, fmt.Errorf("failed to pack length: %v", err)
	}

	// Pack path (len(path) bytes)
	if _, err := buf.Write(path); err != nil {
		return nil, fmt.Errorf("failed to pack path: %v", err)
	}

	// Pack NULL_BYTE (1 byte)
	if err := binary.Write(buf, binary.LittleEndian, NULL_BYTE); err != nil {
		return nil, fmt.Errorf("failed to pack NULL_BYTE: %v", err)
	}
	return buf.Bytes(), nil
}

func validateEntry(templateHashField, depField, cgroupField, hashAlg, fileHash, filePathField string) (string, error) {
	packedDep, err := packPathField([]byte(depField))
	if err != nil {
		return "", fmt.Errorf("Failed to pack 'dep' field")
	}
	packedCgroup, err := packPathField([]byte(cgroupField))
	if err != nil {
		return "", fmt.Errorf("Failed to pack 'cgroup' field")
	}
	decodedFileHash, err := hex.DecodeString(fileHash)
	if err != nil {
		return "", fmt.Errorf("Failed to decode 'file hash' field")
	}
	packedFileHash, err := packHashField(hashAlg, decodedFileHash)
	if err != nil {
		return "", fmt.Errorf("Failed to pack 'file hash' field")
	}
	packedFilePath, err := packPathField([]byte(filePathField))
	if err != nil {
		return "", fmt.Errorf("Failed to pack 'file path' field")
	}

	recomputedTemplateHashSha1, recomputedTemplateHashSha256 := computeEntryTemplateHash(packedDep, packedCgroup, packedFileHash, packedFilePath)

	if recomputedTemplateHashSha1 != templateHashField {
		return "", fmt.Errorf("computed template hash does not match stored entry template hash")
	}
	// return sha256 of entry to be extended
	return recomputedTemplateHashSha256, nil
}
