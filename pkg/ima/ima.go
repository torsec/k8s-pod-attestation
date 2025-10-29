package ima

import (
	"bytes"
	"crypto"
	"fmt"
	"io"
	"os"
	"regexp"
	"strings"
)

const DefaultAsciiPath = "/sys/kernel/security/integrity/ima/ascii_runtime_measurements"
const DefaultBinaryPath = "/sys/kernel/security/integrity/ima/binary_runtime_measurements"

const containerRuntimeDependencies = "/usr/bin/containerd:/usr/bin/containerd:/usr/lib/systemd/systemd:swapper/0"
const ContainerRuntimeName = "/usr/bin/containerd-shim-runc-v2"
const containerRuntimeEngineId = "containerd"

const CgpathTemplateEntryFields = 7
const ColonByte = byte(58) // ASCII code for ":"
const NullByte = byte(0)
const DefaultPCRIndex = 10

func (i *Integrity) isPCRHashAlgo() bool {
	switch i.TemplateHashAlgo {
	case crypto.SHA1, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}

func toHashAlgoString(hash crypto.Hash) string {
	switch hash {
	case crypto.MD5:
		return "md5"
	case crypto.SHA1:
		return "sha1"
	case crypto.SHA224:
		return "sha224"
	case crypto.SHA256:
		return "sha256"
	case crypto.SHA384:
		return "sha384"
	case crypto.SHA512:
		return "sha512"
	default:
		return "unsupported_hash_algo"
	}
}

func (i *Integrity) isFileHashAlgo() bool {
	switch i.FileHashAlgo {
	case crypto.MD5, crypto.SHA1, crypto.SHA224, crypto.SHA256, crypto.SHA384, crypto.SHA512:
		return true
	default:
		return false
	}
}

func (i *Integrity) IsValidPCRIndex() bool {
	return i.pcrIndex >= MinPCRIndex && i.pcrIndex <= MaxPCRIndex
}

func (i *Integrity) IsValidHashConfig() bool {
	return i.isPCRHashAlgo() && i.isFileHashAlgo()
}

func (i *Integrity) TemplateHashSize() int {
	return i.TemplateHashAlgo.Size()
}

func (i *Integrity) FileHashSize() int {
	return i.FileHashAlgo.Size()
}

func (i *Integrity) Aggregate() []byte {
	return i.aggregate
}

func (i *Integrity) Offset() int64 {
	return i.attested
}

func (i *Integrity) Extend(templateHash []byte) error {
	hash := i.TemplateHashAlgo.New()

	toExtend := append(i.aggregate, templateHash...)
	toHashLen := len(toExtend)
	n, err := hash.Write(toExtend)
	if n != toHashLen {
		return fmt.Errorf("failed to write data to hash buffer: wrote only %d < %d bytes", n, toHashLen)
	}
	if err != nil {
		return fmt.Errorf("failed to write data to hash buffer: %v", err)
	}

	i.aggregate = hash.Sum(nil)
	return nil
}

func (i *Integrity) Check(expectedAggregate []byte) error {
	if !bytes.Equal(i.aggregate, expectedAggregate) {
		return fmt.Errorf("IMA measurement log integrity check failed: computed hash does not match expected value")
	}
	return nil
}

func (i *Integrity) CheckFromPCR() error {
	return nil
}

func (i *Integrity) IncrementOffset(n int64) {
	i.attested += n
}

type MeasurementListType string

const (
	File MeasurementListType = "file"
	Raw  MeasurementListType = "raw"
)

type Integrity struct {
	attested  int64  // number of attested bytes of IMA measurement list bytes i.e. starting offset for next measurement list verification
	aggregate []byte // cumulative hash of processed IMA measurements
	tpm       *TPM
	pcrIndex  uint32 // index of PCR reserved to store IMA measurements

	TemplateHashAlgo crypto.Hash // hash algorithm used for template hash computation
	FileHashAlgo     crypto.Hash // hash algorithm used for file hash computation
}

func NewIntegrity(pcrIndex uint32, templateHashAlgo, fileHashAlgo crypto.Hash, tpm *TPM, attested int64) (*Integrity, error) {
	i := &Integrity{
		attested:         attested,
		aggregate:        make([]byte, templateHashAlgo.Size()),
		tpm:              tpm,
		pcrIndex:         pcrIndex,
		TemplateHashAlgo: templateHashAlgo,
		FileHashAlgo:     fileHashAlgo,
	}
	if !i.isPCRHashAlgo() {
		return nil, fmt.Errorf("invalid template hash algorithm configuration: %v", templateHashAlgo)
	}
	if !i.isFileHashAlgo() {
		return nil, fmt.Errorf("invalid file hash algorithm configuration: %v", fileHashAlgo)
	}
	if !i.IsValidPCRIndex() {
		return nil, fmt.Errorf("invalid PCR index for IMA measurements: %d", pcrIndex)
	}
	return i, nil
}

type MeasurementList struct {
	Type MeasurementListType // complete path to measurement list file or raw content
	Path string              // path to measurement list file
	File *os.File            // file handle to measurement list file
	Raw  []byte              // raw content of measurement list
}

func NewMeasurementListFromRaw(raw []byte) *MeasurementList {
	return &MeasurementList{
		Type: Raw,
		Raw:  raw,
	}
}

func NewMeasurementListFromFile(path string) *MeasurementList {
	return &MeasurementList{
		Type: File,
		Path: path,
	}
}

func (ml *MeasurementList) IsRaw() bool {
	return ml.Type == Raw
}

func (ml *MeasurementList) IsFile() bool {
	return ml.Type == File
}

func (ml *MeasurementList) IsOpen() bool {
	if !ml.IsFile() {
		return false
	}
	return ml.File != nil
}

func (ml *MeasurementList) IsReady() bool {
	switch ml.Type {
	case Raw:
		return ml.Raw != nil

	case File:
		return ml.IsOpen()

	default:
		return false
	}
}

func (ml *MeasurementList) Open(offset int64) error {
	if !ml.IsFile() {
		return fmt.Errorf("invalid IMA measurement list type: %v", ml.Type)
	}

	if ml.IsOpen() {
		return nil
	}

	f, err := os.Open(ml.Path)
	if err != nil {
		return fmt.Errorf("failed to open IMA measurement list: %v", err)
	}

	_, err = f.Seek(offset, io.SeekStart)
	if err != nil {
		return fmt.Errorf("failed to seek to offset in IMA measurement list: %v", err)
	}

	ml.File = f
	return nil
}

func (ml *MeasurementList) SetOffset(offset int64) error {
	switch ml.Type {
	case Raw:
		mlLen := int64(len(ml.Raw))
		if offset < 0 || offset > mlLen {
			return fmt.Errorf("invalid offset for raw IMA measurement list: %d", offset)
		}
		ml.Raw = ml.Raw[offset:]
		return nil

	case File:
		if ml.File == nil {
			return fmt.Errorf("failed to read IMA measurement list: file is not open")
		}

		_, err := ml.File.Seek(offset, io.SeekStart)
		if err != nil {
			return fmt.Errorf("failed to seek in IMA measurement list: %v", err)
		}
		return nil

	default:
		return fmt.Errorf("failed to set offset in IMA measurement list: unknown measurement list type: %v", ml.Type)
	}
}

func (ml *MeasurementList) Close() error {
	if !ml.IsFile() {
		return fmt.Errorf("invalid IMA measurement list type: %v", ml.Type)
	}

	if ml.File == nil {
		return nil
	}

	err := ml.File.Close()
	if err != nil {
		return fmt.Errorf("failed to close IMA measurement list: %v", err)
	}

	ml.File = nil
	return nil
}

func (ml *MeasurementList) ReadAll() ([]byte, error) {
	switch ml.Type {
	case Raw:
		return ml.Raw, nil

	case File:
		if ml.File == nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: file is not open")
		}

		buf, err := io.ReadAll(ml.File)
		if err != nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: %v", err)
		}

		return buf, nil

	default:
		return nil, fmt.Errorf("failed to read IMA measurement list: unknown measurement list type: %v", ml.Type)
	}
}

func (ml *MeasurementList) Read(n int) ([]byte, error) {
	switch ml.Type {
	case Raw:
		mlLen := len(ml.Raw)
		if mlLen == 0 {
			return nil, io.EOF
		}
		if mlLen < n {
			return nil, fmt.Errorf("failed to read IMA measurement list: not enough data in raw measurement list")
		}
		buf := ml.Raw[:n]
		ml.Raw = ml.Raw[n:]
		return buf, nil

	case File:
		if ml.File == nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: file is not open")
		}

		buf := make([]byte, n)
		_, err := io.ReadAtLeast(ml.File, buf, n)
		if err != nil {
			if err == io.EOF {
				return nil, err
			} else {
				return nil, fmt.Errorf("failed to read IMA measurement list: %v", err)
			}
		}
		return buf, nil

	default:
		return nil, fmt.Errorf("failed to read IMA measurement list: unknown measurement list type: %v", ml.Type)
	}
}

type Helper struct {
	MeasurementList *MeasurementList
	Integrity       *Integrity
	Template        CGPathTemplate
}

func NewHelper(measurementList *MeasurementList, integrity *Integrity) *Helper {
	h := &Helper{
		MeasurementList: measurementList,
		Integrity:       integrity,
		Template:        CGPathTemplate{},
	}
	return h
}

func (h *Helper) parsePCR() (uint32, error) {
	// read and parse PCR
	pcr, err := h.MeasurementList.Read(pcrSize)
	if err != nil {
		return 0, fmt.Errorf("failed to parse PCR field: %v", err)
	}
	err = h.Template.ParsePCR(pcr, h.Integrity.pcrIndex)
	if err != nil {
		return 0, fmt.Errorf("failed to parse PCR field: %v", err)
	}
	return pcrSize, nil
}

func (h *Helper) parseTemplateHash() (uint32, error) {
	hashSize := h.Integrity.TemplateHashAlgo.Size()
	templateHash, err := h.MeasurementList.Read(hashSize)
	if err != nil {
		return 0, fmt.Errorf("failed to parse template hash: %v", err)
	}
	err = h.Template.ParseTemplateHash(templateHash, hashSize)
	if err != nil {
		return 0, fmt.Errorf("failed to parse template hash: %v", err)
	}
	return uint32(hashSize), nil
}

func (h *Helper) parseTemplateName() (uint32, error) {
	// template name is prefixed by its length field: <nameLen><templateName>
	nameLenField, err := h.MeasurementList.Read(lenFieldSize)
	if err != nil {
		return 0, fmt.Errorf("failed to parse template name: %v", err)
	}
	nameLen, err := parseFieldLen(nameLenField)
	if err != nil {
		return 0, fmt.Errorf("failed to parse template name: %v", err)
	}
	templateName, err := h.MeasurementList.Read(int(nameLen))
	if err != nil {
		return 0, fmt.Errorf("failed to parse template name: %v", err)
	}
	err = h.Template.ParseTemplateName(templateName, nameLen, h.Template.Name())
	if err != nil {
		return 0, fmt.Errorf("failed to parse template name: %v", err)
	}
	return lenFieldSize + nameLen, nil
}

func (h *Helper) parseExtraFieldsLen() (uint32, uint32, error) {
	extraFieldsLenField, err := h.MeasurementList.Read(lenFieldSize)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse extra fields length: %v", err)
	}
	templateFieldsLen, err := parseFieldLen(extraFieldsLenField)
	if err != nil {
		return 0, 0, fmt.Errorf("failed to parse extra fields length: %v", err)
	}
	return templateFieldsLen, lenFieldSize, nil
}

func (h *Helper) parseDependencies() (uint32, error) {
	depLenField, err := h.MeasurementList.Read(lenFieldSize)
	if err != nil {
		return 0, fmt.Errorf("failed to parse dep: %v", err)
	}
	depLen, err := parseFieldLen(depLenField)
	if err != nil {
		return 0, fmt.Errorf("failed to parse dep: %v", err)
	}
	dep, err := h.MeasurementList.Read(int(depLen))
	if err != nil {
		return 0, fmt.Errorf("failed to parse dep: %v", err)
	}
	err = h.Template.ParseDependencies(dep, depLen)
	if err != nil {
		return 0, fmt.Errorf("failed to parse dep: %v", err)
	}
	return lenFieldSize + depLen, nil
}

func (h *Helper) parseCGroup() (uint32, error) {
	cgroupLenField, err := h.MeasurementList.Read(lenFieldSize)
	if err != nil {
		return 0, fmt.Errorf("failed to parse cgroup: %v", err)
	}
	cgroupLen, err := parseFieldLen(cgroupLenField)
	if err != nil {
		return 0, fmt.Errorf("failed to parse cgroup: %v", err)
	}
	cgroup, err := h.MeasurementList.Read(int(cgroupLen))
	if err != nil {
		return 0, fmt.Errorf("failed to parse cgroup: %v", err)
	}
	err = h.Template.ParseCGroup(cgroup, cgroupLen)
	if err != nil {
		return 0, fmt.Errorf("failed to parse cgroup: %v", err)
	}
	return cgroupLen + lenFieldSize, nil
}

func (h *Helper) parseFileHash() (uint32, error) {
	fileHashLenField, err := h.MeasurementList.Read(lenFieldSize)
	if err != nil {
		return 0, fmt.Errorf("failed to parse file hash: %v", err)
	}
	fileHashLen, err := parseFieldLen(fileHashLenField)
	if err != nil {
		return 0, fmt.Errorf("failed to parse file hash: %v", err)
	}
	fileHash, err := h.MeasurementList.Read(int(fileHashLen))
	if err != nil {
		return 0, fmt.Errorf("failed to parse file hash: %v", err)
	}
	err = h.Template.ParseFileHash(fileHash, fileHashLen, h.Integrity.FileHashSize())
	if err != nil {
		return 0, fmt.Errorf("failed to parse file hash: %v", err)
	}
	return fileHashLen + lenFieldSize, nil
}

func (h *Helper) parseFilePath() (uint32, error) {
	filePathLenField, err := h.MeasurementList.Read(lenFieldSize)
	if err != nil {
		return 0, fmt.Errorf("failed to parse file path: %v", err)
	}
	filePathLen, err := parseFieldLen(filePathLenField)
	if err != nil {
		return 0, fmt.Errorf("failed to parse file path: %v", err)
	}
	filePath, err := h.MeasurementList.Read(int(filePathLen))
	if err != nil {
		return 0, fmt.Errorf("failed to parse file path: %v", err)
	}
	err = h.Template.ParseFilePath(filePath, filePathLen)
	if err != nil {
		return 0, fmt.Errorf("failed to parse file path: %v", err)
	}
	return filePathLen + lenFieldSize, nil
}

// | PCR (4 bytes) |
// | Template Hash (variable size) |
// | Template Name Length (4 bytes) |
// | Template Name (variable size) |
// | Template-specific Fields Length (4 bytes) |
// | Template Field 0 Length (4 bytes) |
// | Template Field 0 (variable size) |
// | ... |
// | File Hash Length (4 bytes) |
// | File Hash (variable size) |
// | File Path Length (4 bytes) |
// | File Path (variable size) |

// ParseEntry processes a single IMA measurement list entry from the MeasurementList and populates the Template field of the Helper struct with the parsed data.
func (h *Helper) ParseEntry() (int64, error) {
	var processed uint32 = 0
	var read, extraFieldsLen uint32
	var err error

	// read and parse PCR
	read, err = h.parsePCR()
	if err != nil {
		return 0, fmt.Errorf("failed to parse entry: %v", err)
	}
	processed += read

	// read and parse Template Hash
	read, err = h.parseTemplateHash()
	if err != nil {
		return 0, fmt.Errorf("failed to parse entry: %v", err)
	}
	processed += read

	// read and parse Template Name
	read, err = h.parseTemplateName()
	if err != nil {
		return 0, fmt.Errorf("failed to parse entry: %v", err)
	}
	processed += read

	// read and parse Template Fields Length
	extraFieldsLen, read, err = h.parseExtraFieldsLen()
	if err != nil {
		return 0, fmt.Errorf("failed to parse entry: %v", err)
	}
	processed += read

	// read and parse Template-specific Fields
	// For CGPathTemplate, we expect 4 fields: Dep, Cgroup, File Hash, File Path

	// read and parse Dep Field
	read, err = h.parseDependencies()
	if err != nil {
		return 0, fmt.Errorf("failed to parse entry: %v", err)
	}
	processed += read

	// read and parse Cgroup Field
	read, err = h.parseCGroup()
	if err != nil {
		return 0, fmt.Errorf("failed to parse entry: %v", err)
	}
	processed += read

	// read and parse File Hash Field
	read, err = h.parseFileHash()
	if err != nil {
		return 0, fmt.Errorf("failed to parse entry: %v", err)
	}
	processed += read

	// read and parse File Path Field
	read, err = h.parseFilePath()
	if err != nil {
		return 0, fmt.Errorf("failed to parse entry: %v", err)
	}
	processed += read

	err = h.ValidateTemplateFields(int(extraFieldsLen))
	if err != nil {
		return 0, fmt.Errorf("failed to parse entry: %v", err)
	}

	return int64(processed), nil
}

func (h *Helper) ValidateTemplateFields(expected int) error {
	err := h.Template.ValidateFieldsLen(expected)
	if err != nil {
		return fmt.Errorf("failed to validate template fields: %v", err)
	}
	return nil
}

func (h *Helper) ResetTemplate() {
	h.Template = CGPathTemplate{}
}

func (h *Helper) ValidateEntry() error {
	// Compute expected template hash
	err := h.Template.ValidateEntry(h.Integrity.TemplateHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to validate entry: %v", err)
	}
	return nil
}

// ExtendEntry function to compute the new hash by concatenating previous hash and template hash
func (h *Helper) ExtendEntry() error {
	extended, err := h.Template.extend(h.Integrity.aggregate, h.Integrity.TemplateHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to extend entry: %v", err)
	}
	h.Integrity.aggregate = extended

	return nil
}

func (h *Helper) SetAttestationOffset() error {
	err := h.MeasurementList.SetOffset(h.Integrity.attested)
	if err != nil {
		return fmt.Errorf("failed to set attestation offset in measurement list: %v", err)
	}
	return nil
}

func (h *Helper) MeasurementListTPMAttestation() error {
	if !h.Integrity.tpm.IsOpen() {
		return fmt.Errorf("TPM is not open")
	}
	// read PCR value from TPM
	pcrs, err := h.Integrity.tpm.ReadPCRs([]int{int(h.Integrity.pcrIndex)}, h.Integrity.TemplateHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to read PCR from TPM: %v", err)
	}
	expected := pcrs[h.Integrity.pcrIndex]
	return h.MeasurementListAttestation(expected)
}

func (h *Helper) MeasurementListAttestation(expected []byte) error {
	if len(expected) != h.Integrity.TemplateHashSize() {
		return fmt.Errorf("expected aggregate size does not match template hash size")
	}

	if !h.MeasurementList.IsReady() {
		return fmt.Errorf("IMA measurement list is not ready for attestation")
	}

	var err error
	var newOffset, read int64 = 0, 0
	// process measurement list entries until EOF
	for {
		read, err = h.ParseEntry()
		if err != nil {
			return fmt.Errorf("failed to process measurement list entry: %v", err)
		}
		err = h.ValidateEntry()
		if err != nil {
			return fmt.Errorf("failed to validate measurement list entry: %v", err)
		}
		newOffset += read

		err = h.ExtendEntry()
		if err != nil {
			return fmt.Errorf("failed to extend measurement list entry: %v", err)
		}

		err = h.Integrity.Check(expected)
		if err == nil {
			h.Integrity.IncrementOffset(newOffset)
			return nil
		}
		h.ResetTemplate()
	}
}

//func NewHelper(asciiPath, binaryPath string, templateHashAlgo crypto.Hash, fileHashAlgo crypto.Hash) (*Helper, error) {
//	h := &Helper{
//		MeasurementList{
//			Type: "",
//			Path: "",
//			File: nil,
//			Raw:  nil,
//		},
//	}
//
//	if asciiPath == "" {
//		h.AsciiPath = DefaultAsciiPath
//	}
//	if binaryPath == "" {
//		h.BinaryPath = DefaultBinaryPath
//	}
//	if templateHashAlgo == crypto.Hash(0) {
//		h.TemplateHashAlgo = crypto.SHA1
//	}
//	if fileHashAlgo == crypto.Hash(0) {
//		h.FileHashAlgo = crypto.SHA256
//	}
//
//	if !isPCRHashAlgo(h.TemplateHashAlgo) {
//		return nil, fmt.Errorf("invalid template hash algorithm")
//	}
//
//	if !isFileHashAlgo(h.FileHashAlgo) {
//		return nil, fmt.Errorf("invalid file hash algorithm")
//	}
//
//	return h, nil
//}

// extractFileHashDigest extracts the algorithm (e.g., "sha256") and the actual hex digest from a string with the format "sha<algo>:<hex_digest>"
//func extractFileHashDigest(input string) (string, string, error) {
//	re := regexp.MustCompile(`^sha[0-9]+:`)
//
//	// Check if the input matches the expected format
//	if matches := re.FindStringSubmatch(input); matches != nil {
//		fileHashElements := strings.Split(input, ":")
//		hashAlgo := fileHashElements[0]
//		hexDigest := fileHashElements[1]
//
//		return hashAlgo, hexDigest, nil
//	}
//	return "", "", fmt.Errorf("input does not have a valid sha<algo>:<hex_digest> format")
//}
//
//// MeasurementLogValidation checks the integrity of the IMA measurement logger against the received Quote and returns the entries related to the pod being attested for statical analysis of executed software and the AttestationResult
//func MeasurementLogValidation(measurementLog []byte, offset *int64, targetPcr []byte, bankHash crypto.Hash, previousAggregate []byte, podUid string) (int64, []model.IMAEntry, []model.IMAEntry, error) {
//	isMeasurementLogValid := false
//
//	uniquePodEntries := make(map[string]model.IMAEntry)
//	uniqueContainerRuntimeEntries := make(map[string]model.IMAEntry)
//
//	scanner := bufio.NewScanner(bytes.NewReader(measurementLog[*offset:]))
//
//	previousHash := make([]byte, bankHash.Size())
//
//	if previousAggregate != nil {
//		previousHash = previousAggregate
//	}
//
//	for scanner.Scan() {
//		line := scanner.Text()
//
//		if !isMeasurementLogValid {
//			*offset += int64(len(line) + 1) // +1 for the newline character
//		}
//
//		entryFields := strings.Fields(line)
//		if len(entryFields) < CgpathTemplateEntryFields {
//			return -1, nil, nil, fmt.Errorf("IMA measurement log integrity check failed: entry %d not compliant with template: %s", idx, imaLine)
//		}
//
//		templateHashField := entryFields[1]
//		depField := entryFields[3]
//		cgroupPathField := entryFields[4]
//		fileHashField := entryFields[5]
//		filePathField := entryFields[6]
//
//		hashAlgo, fileHash, err := extractFileHashDigest(fileHashField)
//		if err != nil {
//			return -1, nil, nil, fmt.Errorf("IMA measurement log integrity check failed: entry: %d file hash is invalid: %s", idx, imaLine)
//		}
//
//		extendValue, err := validateEntry(templateHashField, depField, cgroupPathField, hashAlgo, fileHash, filePathField)
//		if err != nil {
//			return -1, nil, nil, fmt.Errorf("IMA measurement log integrity check failed: entry: %d is invalid: %s", idx, imaLine)
//		}
//
//		// Use the helper function to extend ML cumulative hash with the newly computed template hash
//		extendedHash, err := extendEntry(previousHash, extendValue)
//		if err != nil {
//			return -1, nil, nil, fmt.Errorf("error computing hash at index %d: %v\n", idx, err)
//		}
//
//		// Update the previous hash for the next iteration
//		previousHash = extendedHash
//		if !isMeasurementLogValid && hex.EncodeToString(extendedHash) == targetPcr {
//			isMeasurementLogValid = true
//		}
//
//		// check if entry belongs to container or is pure a host measurement, otherwise after having computed the extend hash, go to next entry in IMA ML
//		if !strings.Contains(depField, containerRuntimeEngineId) {
//			continue
//		}
//
//		// entry is host container-related not a pod entry
//		if filePathField == ContainerRuntimeName || depField == containerRuntimeDependencies {
//			// Create a unique key by combining filePath and fileHash
//			entryKey := fmt.Sprintf("%s:%s", filePathField, fileHash)
//
//			// Add the entry to the map if it doesn't exist
//			if _, exists := uniqueContainerRuntimeEntries[entryKey]; !exists {
//				uniqueContainerRuntimeEntries[entryKey] = model.IMAEntry{
//					FilePath: filePathField,
//					FileHash: fileHash,
//				}
//			}
//			continue
//		}
//
//		// Check if the cgroup path contains the podUID
//		if checkPodUidMatch(cgroupPathField, podUid) {
//			// Create a unique key by combining filePath and fileHash
//			entryKey := fmt.Sprintf("%s:%s", filePathField, fileHash)
//			// Add the entry to the map if it doesn't exist
//			if _, exists := uniquePodEntries[entryKey]; !exists {
//				uniquePodEntries[entryKey] = model.IMAEntry{
//					FilePath: filePathField,
//					FileHash: fileHash,
//				}
//			}
//		}
//	}
//
//	// Convert the final hash to a hex string for comparison
//	cumulativeHashHex := hex.EncodeToString(previousHash)
//	// Compare the computed hash with the provided PCR10Digest
//	if cumulativeHashHex != targetPcr {
//		return -1, nil, nil, fmt.Errorf("IMA measurement log integrity check failed: computed hash does not match quote value")
//	}
//
//	// Convert the unique entries back to a slice
//	podEntries := make([]model.IMAEntry, 0, len(uniquePodEntries))
//	for _, entry := range uniquePodEntries {
//		podEntries = append(podEntries, entry)
//	}
//
//	containerRuntimeEntries := make([]model.IMAEntry, 0, len(uniqueContainerRuntimeEntries))
//	for _, entry := range uniqueContainerRuntimeEntries {
//		containerRuntimeEntries = append(containerRuntimeEntries, entry)
//	}
//
//	// Return the collected IMA pod entries
//	return offset, podEntries, containerRuntimeEntries, nil
//}

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
