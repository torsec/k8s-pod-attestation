package ima

import (
	"bytes"
	"crypto"
	"fmt"
	"slices"
)

const CgPathExtraLenFields = 4

// | PCR (4 bytes) |
// | Template Hash (variable size) |
// | Template Name Length (4 bytes) |
// | Template Name (variable size) |
// | Template-specific Fields Length (4 bytes) |
// | Template Field 0 Length (4 bytes) |
// | Template Field 0 (variable size) |
// | ... |
// | file Hash Length (4 bytes) |
// | file Hash (variable size) |
// | file Path Length (4 bytes) |
// | file Path (variable size) |

type CgPathTemplate struct {
	BasicEntry
	CgPathExtraFields
}

// CgPathExtraFields represents the extra fields for the ima-cgpath non-standard IMA template
type CgPathExtraFields struct {
	Dependencies []byte
	CGroup       []byte
	FileHash     []byte
	FilePath     []byte
}

func (cg *CgPathTemplate) Print() {
	fmt.Printf("IMA Measurement Entry:\n")
	fmt.Printf("  PCR: %d\n", cg.PCR)
	fmt.Printf("  Template Hash: %x\n", cg.TemplateHash)
	fmt.Printf("  Template Name: %s\n", cg.TemplateName)
	fmt.Printf("  Dependencies: %s\n", cg.DepToString())
	fmt.Printf("  CGroup: %s\n", cg.CGroupToString())
	fmt.Printf("  file Hash: %s\n", cg.FileHashToString())
	fmt.Printf("  file Path: %s\n", cg.FilePathToString())
}

func (cg *CgPathTemplate) GetTemplateHash() []byte {
	return cg.TemplateHash
}

func (cg *CgPathTemplate) Name() []byte {
	return []byte("ima-cgpath")
}

func (cg *CgPathTemplate) parseFilePath(buf []byte, filePathLen uint32) error {
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

func (cg *CgPathTemplate) FilePathToString() string {
	filePath := string(cg.FilePath[:len(cg.FilePath)-1]) // remove NULL_BYTE
	return filePath
}

func (cg *CgPathTemplate) MakeTemplateHash(hashAlgo crypto.Hash) ([]byte, error) {
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

func (cg *CgPathTemplate) DepToString() string {
	dep := string(cg.CgPathExtraFields.Dependencies[:len(cg.CgPathExtraFields.Dependencies)-1]) // remove NULL_BYTE
	return dep
}

func (cg *CgPathTemplate) CGroupToString() string {
	cgroup := string(cg.CgPathExtraFields.CGroup[:len(cg.CgPathExtraFields.CGroup)-1]) // remove NULL_BYTE
	return cgroup
}

func (cg *CgPathTemplate) FileHashToString() string {
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

func (cg *CgPathTemplate) ValidateFieldsLen(expected int) error {
	actual := cg.Size() - cg.BasicEntry.Size()
	if actual != expected {
		return fmt.Errorf("invalid extra fields length: got %d, want %d", actual, expected)
	}
	return nil
}

func (cg *CgPathTemplate) ParseEntry(r FieldReader, reservedPcr uint32, templateHashSize, fileHashSize int) error {
	var err error
	err = cg.ParsePCR(r, reservedPcr)
	if err != nil {
		return fmt.Errorf("failed to parse entry: %v", err)
	}
	err = cg.ParseTemplateHash(r, templateHashSize)
	if err != nil {
		return fmt.Errorf("failed to parse entry: %v", err)
	}
	err = cg.ParseTemplateName(r)
	if err != nil {
		return fmt.Errorf("failed to parse entry: %v", err)
	}
	err = cg.ParseExtraFields(r, fileHashSize)
	if err != nil {
		return fmt.Errorf("failed to parse entry: %v", err)
	}
	return nil
}

func (cg *CgPathTemplate) Clear() {
	cg.BasicEntry = BasicEntry{}
	cg.CgPathExtraFields = CgPathExtraFields{}
}

func (cg *CgPathTemplate) ValidateEntry(templateHashAlgo crypto.Hash) error {
	computedTemplateHash, err := cg.MakeTemplateHash(templateHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute template hash: %v", err)
	}
	if bytes.Compare(computedTemplateHash, cg.TemplateHash) != 0 {
		return fmt.Errorf("template hash mismatch: got %x, want %x", cg.BasicEntry.TemplateHash, computedTemplateHash)
	}
	return nil
}

func (cg *CgPathTemplate) parseDependencies(dep []byte, depLen uint32) error {
	bufSize := len(dep)
	if uint32(bufSize) != depLen {
		return fmt.Errorf("invalid dependencies field size: got %d, want %d", bufSize, depLen)
	}
	depsField := make([]byte, depLen)
	copy(depsField, dep)
	cg.CgPathExtraFields.Dependencies = depsField
	return nil
}

func (cg *CgPathTemplate) parseCGroup(buf []byte, cgroupPathLen uint32) error {
	bufSize := len(buf)
	if uint32(bufSize) != cgroupPathLen {
		return fmt.Errorf("invalid cgroup path field size: got %d, want %d", bufSize, cgroupPathLen)
	}
	cgroupPathField := make([]byte, cgroupPathLen)
	copy(cgroupPathField, buf)
	cg.CgPathExtraFields.CGroup = cgroupPathField
	return nil
}

func (cg *CgPathTemplate) parseFileHash(fileHash []byte, fileHashLen uint32, hashSize int) error {
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

	cg.CgPathExtraFields.FileHash = fileHashField
	return nil
}

func (cg *CgPathTemplate) ParsePCR(r FieldReader, reservedPcr uint32) error {
	buf, err := r.ReadFixed(pcrSize)
	if err != nil {
		return fmt.Errorf("failed to read PCR field: %v", err)
	}
	return cg.BasicEntry.parsePCR(buf, reservedPcr)
}

func (cg *CgPathTemplate) ParseTemplateHash(r FieldReader, hashSize int) error {
	buf, err := r.ReadFixed(hashSize)
	if err != nil {
		return fmt.Errorf("failed to read template hash field: %v", err)
	}
	return cg.BasicEntry.parseTemplateHash(buf, hashSize)
}

func (cg *CgPathTemplate) ParseTemplateName(r FieldReader) error {
	templateName, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read template name field: %v", err)
	}
	return cg.BasicEntry.parseTemplateName(templateName, uint32(len(templateName)), cg.Name())
}

func (cg *CgPathTemplate) ParseExtraFieldsLen(r FieldReader) (uint32, error) {
	extraFieldsLen, err := r.ReadLen()
	if err != nil {
		return 0, fmt.Errorf("failed to read extra fields length: %v", err)
	}
	return extraFieldsLen, nil
}

func (cg *CgPathTemplate) ParseDependencies(r FieldReader) error {
	dep, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read dependencies field: %v", err)
	}
	return cg.parseDependencies(dep, uint32(len(dep)))
}

func (cg *CgPathTemplate) ParseCGroup(r FieldReader) error {
	cgroup, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read cgroup field: %v", err)
	}
	return cg.parseCGroup(cgroup, uint32(len(cgroup)))
}

func (cg *CgPathTemplate) ParseFileHash(r FieldReader, hashSize int) error {
	fileHash, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read file hash field: %v", err)
	}
	return cg.parseFileHash(fileHash, uint32(len(fileHash)), hashSize)
}

func (cg *CgPathTemplate) ParseFilePath(r FieldReader) error {
	filePath, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read file path field: %v", err)
	}
	return cg.parseFilePath(filePath, uint32(len(filePath)))
}

func (cg *CgPathTemplate) ParseExtraFields(r FieldReader, fileHashSize int) error {
	var err error
	// extra fields length
	extraFieldsLen, err := cg.ParseExtraFieldsLen(r)
	if err != nil {
		return fmt.Errorf("failed to read extra fields length: %v", err)
	}
	// Dependencies
	err = cg.ParseDependencies(r)
	if err != nil {
		return fmt.Errorf("failed to read dependencies field: %v", err)
	}
	// Cgroup
	err = cg.ParseCGroup(r)
	if err != nil {
		return fmt.Errorf("failed to read cgroup field: %v", err)
	}
	// File hash
	err = cg.ParseFileHash(r, fileHashSize)
	if err != nil {
		return fmt.Errorf("failed to read file hash field: %v", err)
	}
	// File path
	err = cg.ParseFilePath(r)
	if err != nil {
		return fmt.Errorf("failed to read file path field: %v", err)
	}

	err = cg.ValidateFieldsLen(int(extraFieldsLen))
	if err != nil {
		return fmt.Errorf("failed to validate extra fields length: %v", err)
	}
	return nil
}

func (cg *CgPathTemplate) Size() int {
	size := cg.BasicEntry.Size()
	size += len(cg.CgPathExtraFields.Dependencies)
	size += len(cg.CgPathExtraFields.CGroup)
	size += len(cg.CgPathExtraFields.FileHash)
	size += len(cg.CgPathExtraFields.FilePath)
	size += CgPathExtraLenFields * lenFieldSize
	return size
}

func (cg *CgPathTemplate) RawFileHashAlgo() ([]byte, error) {
	// fileHash structure is <hashAlgoField>:<NULL_BYTE><digest>
	var i int
	for i = 0; i < len(cg.FileHash); i++ {
		if cg.FileHash[i] == ColonByte {
			return cg.CgPathExtraFields.FileHash[:i], nil
		}
	}
	return nil, fmt.Errorf("invalid file hash field")
}

func (cg *CgPathTemplate) FileHashDigestToString() string {
	digest, err := cg.RawFileHashDigest()
	if err != nil {
		return "invalid_file_hash"
	}
	return fmt.Sprintf("%x", digest)
}

func (cg *CgPathTemplate) RawFileHashDigest() ([]byte, error) {
	// fileHash structure is <hashAlgoField>:<NULL_BYTE><digest>
	var i int
	for i = 1; i < len(cg.FileHash); i++ {
		if cg.FileHash[i-1] == NullByte {
			return cg.FileHash[i:], nil
		}
	}
	return nil, fmt.Errorf("invalid file hash field")
}

const (
	Containerd = "containerd"
	Dockerd    = "dockerd"
)

var containerRuntimes = map[string]ContainerRuntimeDetails{
	Containerd: {
		Executable: []byte("/usr/bin/containerd"),
		Dependencies: [][]byte{
			[]byte("/usr/bin/containerd:/usr/bin/containerd:/usr/lib/systemd/systemd:swapper/0"),
			[]byte("/usr/bin/runc:/usr/bin/runc:/usr/bin/containerd-shim-runc-v2:/usr/lib/systemd/systemd:swapper/0"),
		},
	},
	Dockerd: {
		Executable: []byte("/usr/bin/dockerd"),
		Dependencies: [][]byte{
			[]byte("/usr/bin/dockerd:/usr/bin/dockerd:/usr/lib/systemd/systemd:swapper/0"),
		},
	},
}

type ContainerRuntimeDetails struct {
	Executable   []byte
	Dependencies [][]byte
}

type CgPathTarget struct {
	podUid []byte
	ContainerRuntimeDetails
	Matches
}

func (t *CgPathTarget) GetMatches() Matches {
	return t.Matches
}

func (t *CgPathTarget) CheckMatch(tmpl Template) (bool, error) {
	cgTmpl, ok := tmpl.(*CgPathTemplate)
	if !ok {
		return false, fmt.Errorf("failed to parse Template into ima-cgpath template")
	}

	if t.IsContainerRuntimeDep(cgTmpl.Dependencies) || t.IsContainerRuntimeExecutable(cgTmpl.FilePath) {
		t.AddMatch(ContainerRuntime, Measurement{
			FilePath: cgTmpl.FilePathToString(),
			FileHash: cgTmpl.FileHashDigestToString(),
		})
		return true, nil
	}

	if t.IsPodUidInCGroup(cgTmpl.CGroup) {
		t.AddMatch(Pod, Measurement{
			FilePath: cgTmpl.FilePathToString(),
			FileHash: cgTmpl.FileHashDigestToString(),
		})
		return true, nil
	}
	return false, nil
}

func NewCGPathTarget(podUid []byte, containerRuntimeName string) (*CgPathTarget, error) {
	cr, ok := containerRuntimes[containerRuntimeName]
	if !ok {
		return nil, fmt.Errorf("unknown container runtime %q", containerRuntimeName)
	}

	return &CgPathTarget{
		podUid:                  podUid,
		ContainerRuntimeDetails: cr,
		Matches:                 *NewMatches(),
	}, nil
}

func (t *CgPathTarget) IsContainerRuntimeDep(dep []byte) bool {
	for _, d := range t.ContainerRuntimeDetails.Dependencies {
		if bytes.Contains(dep, d) {
			return true
		}
	}
	return false
}

func (t *CgPathTarget) IsContainerRuntimeExecutable(filePath []byte) bool {
	return bytes.Contains(filePath, t.ContainerRuntimeDetails.Executable)
}

func (t *CgPathTarget) IsPodUidInCGroup(cgroup []byte) bool {
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
