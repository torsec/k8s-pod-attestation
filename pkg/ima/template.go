package ima

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
	"slices"
)

const lenFieldSize = 4 // size of field containing length of variable-length fields
const pcrSize = 4

func isValidFileHashAlgo(hashAlgo []byte) bool {
	switch string(hashAlgo) {
	case "sha1", "sha256", "sha384", "sha512", "md5":
		return true
	default:
		return false
	}
}

type BasicEntry struct {
	PCR          uint32
	TemplateHash []byte
	TemplateName []byte
}

func (b *BasicEntry) extend(aggregate []byte, hashAlgo crypto.Hash) ([]byte, error) {
	hash := hashAlgo.New()
	toExtend := append(aggregate, b.TemplateHash...)
	toExtendLen := len(toExtend)

	// Compute the new hash
	n, err := hash.Write(toExtend)
	if n != toExtendLen {
		return nil, fmt.Errorf("failed to write data to hash buffer: wrote only %d < %d bytes", n, toExtendLen)
	}
	if err != nil {
		return nil, fmt.Errorf("failed to write data to hash buffer: %v", err)
	}

	extended := hash.Sum(nil)
	return extended, nil
}

func (b *BasicEntry) ParsePCR(buf []byte, reservedPcr uint32) error {
	bufSize := len(buf)

	if bufSize != pcrSize {
		return fmt.Errorf("invalid entry buffer size: got %d, want %d", bufSize, pcrSize)
	}

	pcr := binary.LittleEndian.Uint32(buf)
	if pcr != reservedPcr {
		return fmt.Errorf("unexpected PCR value: got %d, want %d", b.PCR, reservedPcr)
	}
	b.PCR = pcr
	return nil
}

func (b *BasicEntry) ParseTemplateHash(buf []byte, hashSize int) error {
	bufSize := len(buf)

	if bufSize != hashSize {
		return fmt.Errorf("invalid template hash size: got %d, want %d", bufSize, hashSize)
	}

	b.TemplateHash = make([]byte, hashSize)
	copy(b.TemplateHash, buf)
	return nil
}

func (cg *CGPathTemplate) Print() {
	fmt.Printf("IMA Measurement Entry:\n")
	fmt.Printf("  PCR: %d\n", cg.PCR)
	fmt.Printf("  Template Hash: %x\n", cg.TemplateHash)
	fmt.Printf("  Template Name: %s\n", cg.TemplateName)
	fmt.Printf("  Dependencies: %s\n", cg.DepToString())
	fmt.Printf("  CGroup: %s\n", cg.CGroupToString())
	fmt.Printf("  File Hash: %s\n", cg.FileHashToString())
	fmt.Printf("  File Path: %s\n", cg.FilePathToString())
}

func (b *BasicEntry) ParseTemplateName(buf []byte, nameLen uint32, expected []byte) error {
	bufSize := len(buf)
	if uint32(bufSize) != nameLen {
		return fmt.Errorf("invalid template name size: got %d, want %d", bufSize, nameLen)
	}
	nameField := make([]byte, nameLen)
	copy(nameField, buf)
	if bytes.Compare(nameField, expected) != 0 {
		return fmt.Errorf("unexpected template name: got %s, want %s", nameField, expected)
	}
	b.TemplateName = nameField
	return nil
}

/*
type Template[ExtraFields any] interface {
	Name() []byte
	Fields() ExtraFields
	Parse([]byte) (ExtraFields, error)
}
*/

const (
	Containerd = "containerd"
	Dockerd    = "dockerd"
)

var containerRuntimes = map[string]ContainerRuntime{
	Containerd: {
		Executable:   []byte("/usr/bin/containerd-shim-runc-v2"),
		Dependencies: []byte("/usr/bin/containerd:/usr/bin/containerd:/usr/lib/systemd/systemd:swapper/0"),
	},
	Dockerd: {
		Executable:   []byte("/usr/bin/runc"),
		Dependencies: []byte("/usr/bin/dockerd:/usr/bin/dockerd:/usr/lib/systemd/systemd:swapper/0"),
	},
}

type ContainerRuntime struct {
	Executable   []byte
	Dependencies []byte
}

// CGPathExtraFields represents the extra fields for the ima-cgpath non-standard IMA template
type CGPathExtraFields struct {
	Dependencies []byte
	CGroup       []byte
	FileHash     []byte
	FilePath     []byte
}

type Target struct {
	podUid []byte
	ContainerRuntime
}

func NewTarget(podUid []byte, containerRuntimeName string) (*Target, error) {
	cr, ok := containerRuntimes[containerRuntimeName]
	if !ok {
		return nil, fmt.Errorf("unknown container runtime %q", containerRuntimeName)
	}

	return &Target{
		podUid:           podUid,
		ContainerRuntime: cr,
	}, nil
}

func (t *Target) IsContainerRuntimeDep(dep []byte) bool {
	return bytes.Equal(t.ContainerRuntime.Dependencies, dep)
}

func (t *Target) IsContainerRuntimeExecutable(filePath []byte) bool {
	return bytes.Equal(t.ContainerRuntime.Executable, filePath)
}

func (t *Target) IsPodUidInCGroup(cgroup []byte) bool {
	// Replace dashes with underscores in podUid
	adjustedPodUid := bytes.ReplaceAll(t.podUid, []byte("-"), []byte("_"))

	// Build the pattern we want to find: "-pod<adjustedPodUid>.slice"
	pattern := slices.Concat([]byte("-pod"), adjustedPodUid, []byte(".slice"))

	// Search for the pattern in path
	if i := bytes.Index(cgroup, pattern); i >= 0 {
		if bytes.Contains(cgroup[:i], []byte("kubepods")) {
			return true
		}
	}
	return false
}

type CGPathTemplate struct {
	BasicEntry
	CGPathExtraFields
	Target *Target
}

func (cg *CGPathTemplate) Name() []byte {
	return []byte("ima-cgpath")
}

func (cg *CGPathTemplate) Fields() CGPathExtraFields {
	return cg.CGPathExtraFields
}

func (cg *CGPathTemplate) ParseFilePath(buf []byte, filePathLen uint32) error {
	bufSize := len(buf)
	if uint32(bufSize) != filePathLen {
		return fmt.Errorf("invalid file path size: got %d, want %d", bufSize, filePathLen)
	}
	err := validateFilePath(buf)
	if err != nil {
		return fmt.Errorf("invalid file path field: %s", err)
	}
	filePathField := make([]byte, filePathLen)
	copy(filePathField, buf)
	cg.FilePath = filePathField
	return nil
}

func (cg *CGPathTemplate) FilePathToString() string {
	filePath := string(cg.FilePath[:len(cg.FilePath)-1]) // remove NULL_BYTE
	return filePath
}

func (cg *CGPathTemplate) MakeTemplateHash(hashAlgo crypto.Hash) ([]byte, error) {
	packedDep, err := packPath(cg.Dependencies)
	if err != nil {
		return nil, fmt.Errorf("failed to pack dependencies field: %v", err)
	}

	packedCgroup, err := packPath(cg.CGroup)
	if err != nil {
		return nil, fmt.Errorf("failed to pack cgroup path field: %v", err)
	}

	packedFileHash, err := packHash(cg.FileHash)
	if err != nil {
		return nil, fmt.Errorf("failed to pack file hash field: %v", err)
	}

	packedFilePath, err := packPath(cg.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to pack file path field: %v", err)
	}

	packedTemplateEntry := slices.Concat(packedDep, packedCgroup, packedFileHash, packedFilePath)
	hash := hashAlgo.New()
	_, err = hash.Write(packedTemplateEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to compute template hash: %v", err)
	}

	return hash.Sum(nil), nil
}

func (cg *CGPathTemplate) DepToString() string {
	dep := string(cg.CGPathExtraFields.Dependencies[:len(cg.CGPathExtraFields.Dependencies)-1]) // remove NULL_BYTE
	return dep
}

func (cg *CGPathTemplate) CGroupToString() string {
	cgroup := string(cg.CGPathExtraFields.CGroup[:len(cg.CGPathExtraFields.CGroup)-1]) // remove NULL_BYTE
	return cgroup
}

func (cg *CGPathTemplate) FileHashToString() string {
	hashAlgo, err := cg.RawFileHashAlgo()
	if err != nil {
		return "invalid_file_hash"
	}
	digest, err := cg.RawFileHashDigest()
	if err != nil {
		return "invalid_file_hash"
	}
	fileHash := fmt.Sprintf("%s:%x", hashAlgo, digest)
	return fileHash
}

func (cg *CGPathTemplate) ValidateFieldsLen(expected int) error {
	formattedFields := slices.Concat(cg.CGPathExtraFields.Dependencies, cg.CGPathExtraFields.CGroup, cg.CGPathExtraFields.FileHash, cg.CGPathExtraFields.FilePath)
	actual := len(formattedFields) + 4*lenFieldSize
	if expected != actual {
		return fmt.Errorf("invalid extra fields length: got %d, want %d", actual, expected)
	}
	return nil
}

func (cg *CGPathTemplate) ValidateEntry(templateHashAlgo crypto.Hash) error {
	computedTemplateHash, err := cg.MakeTemplateHash(templateHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute template hash: %v", err)
	}
	if bytes.Compare(computedTemplateHash, cg.TemplateHash) != 0 {
		return fmt.Errorf("template hash mismatch: got %x, want %x", cg.BasicEntry.TemplateHash, computedTemplateHash)
	}
	return nil
}

func (cg *CGPathTemplate) ParseDependencies(buf []byte, depsLen uint32) error {
	bufSize := len(buf)
	if uint32(bufSize) != depsLen {
		return fmt.Errorf("invalid dependencies field size: got %d, want %d", bufSize, depsLen)
	}
	depsField := make([]byte, depsLen)
	copy(depsField, buf)
	cg.CGPathExtraFields.Dependencies = depsField
	return nil
}

func (cg *CGPathTemplate) ParseCGroup(buf []byte, cgroupPathLen uint32) error {
	bufSize := len(buf)
	if uint32(bufSize) != cgroupPathLen {
		return fmt.Errorf("invalid cgroup path field size: got %d, want %d", bufSize, cgroupPathLen)
	}
	cgroupPathField := make([]byte, cgroupPathLen)
	copy(cgroupPathField, buf)
	cg.CGPathExtraFields.CGroup = cgroupPathField
	return nil
}

func (cg *CGPathTemplate) ParseFileHash(fileHash []byte, fileHashLen uint32, hashSize int) error {
	fileHashSize := len(fileHash)

	if uint32(fileHashSize) != fileHashLen {
		return fmt.Errorf("invalid file hash field size: got %d, want %d", fileHashSize, fileHashLen)
	}

	// fileHash structure is <hashAlgoField>:<NULL_BYTE><digest>
	err := validateFileHash(fileHash, hashSize)
	if err != nil {
		return fmt.Errorf("invalid file hash field: %s", err)
	}

	fileHashField := make([]byte, fileHashLen)
	copy(fileHashField, fileHash)

	cg.CGPathExtraFields.FileHash = fileHashField
	return nil
}

func (cg *CGPathTemplate) RawFileHashAlgo() ([]byte, error) {
	// fileHash structure is <hashAlgoField>:<NULL_BYTE><digest>
	var i int
	for i = 0; i < len(cg.FileHash); i++ {
		if cg.FileHash[i] == ColonByte {
			return cg.CGPathExtraFields.FileHash[:i], nil
		}
	}
	return nil, fmt.Errorf("invalid file hash field")
}

func (cg *CGPathTemplate) RawFileHashDigest() ([]byte, error) {
	// fileHash structure is <hashAlgoField>:<NULL_BYTE><digest>
	var i int
	for i = 1; i < len(cg.FileHash); i++ {
		if cg.FileHash[i-1] == NullByte {
			return cg.FileHash[i:], nil
		}
	}
	return nil, fmt.Errorf("invalid file hash field")
}

// parseFieldLen parses a length field from a byte buffer and returns the length as uint32.
func parseFieldLen(field []byte) (uint32, error) {
	fieldSize := len(field)
	if fieldSize != lenFieldSize {
		return 0, fmt.Errorf("invalid length field size: got %d, want %d", fieldSize, lenFieldSize)
	}
	fieldLen := binary.LittleEndian.Uint32(field)
	return fieldLen, nil
}

// ----------------------------------------------------
// Helper functions for packing fields
// ----------------------------------------------------

func packPath(path []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	pathLen := uint32(len(path))
	if err := binary.Write(buf, binary.LittleEndian, pathLen); err != nil {
		return nil, fmt.Errorf("failed to pack total length: %v", err)
	}
	// Pack path (len(path) bytes)
	n, err := buf.Write(path)
	if err != nil {
		return nil, fmt.Errorf("failed to pack path: %v", err)
	}
	if n != int(pathLen) {
		return nil, fmt.Errorf("failed to pack complete path: wrote %d, want %d", n, pathLen)
	}

	return buf.Bytes(), nil
}

func packHash(hash []byte) ([]byte, error) {
	buf := new(bytes.Buffer)
	hashLen := uint32(len(hash))
	if err := binary.Write(buf, binary.LittleEndian, hashLen); err != nil {
		return nil, fmt.Errorf("failed to pack total length: %v", err)
	}
	// Pack hash (len(hash) bytes)
	n, err := buf.Write(hash)
	if err != nil {
		return nil, fmt.Errorf("failed to pack hash: %v", err)
	}
	if n != int(hashLen) {
		return nil, fmt.Errorf("failed to pack complete hash: wrote %d, want %d", n, hashLen)
	}
	return buf.Bytes(), nil
}

func validateFilePath(path []byte) error {
	// filePath structure is <path><NULL_BYTE>
	pathSize := len(path)
	if pathSize == 0 {
		return fmt.Errorf("file path is empty")
	}
	if path[pathSize-1] != NullByte {
		return fmt.Errorf("file path does not end with NULL_BYTE")
	}
	return nil
}

func validateFileHash(fileHash []byte, hashSize int) error {
	// fileHash structure is <hashAlgoField>:<NULL_BYTE><digest>
	var i, j int
	var hashAlgoField []byte
	fileHashSize := len(fileHash)

	for i = 0; i < fileHashSize; i++ {
		if fileHash[i] == ColonByte {
			break
		}
		hashAlgoField = append(hashAlgoField, fileHash[i])
	}
	if !isValidFileHashAlgo(hashAlgoField) {
		return fmt.Errorf("invalid file hash algorithm: %s", hashAlgoField)
	}

	for j = i + 1; j < fileHashSize; j++ {
		if fileHash[j] == NullByte {
			break
		}
	}
	// prefix is <hashAlgoField>:<NULL_BYTE>
	prefixLen := j + 1
	if fileHashSize-prefixLen != hashSize {
		return fmt.Errorf("invalid file hash digest size: got %d, want %d", fileHashSize-j-1, hashSize)
	}
	return nil
}
