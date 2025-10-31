package ima

import (
	"bytes"
	"crypto"
	"fmt"
	"slices"
)

const NgExtraLenFields = 2

type NgTemplate struct {
	BasicEntry
	NgExtraFields
}

type NgExtraFields struct {
	FileHash []byte
	FilePath []byte
}

func (ng *NgTemplate) ParsePCR(r FieldReader, reservedPcr uint32) error {
	buf, err := r.ReadFixed(pcrSize)
	if err != nil {
		return fmt.Errorf("failed to read PCR field: %v", err)
	}
	return ng.BasicEntry.parsePCR(buf, reservedPcr)
}

func (ng *NgTemplate) ParseTemplateHash(r FieldReader, hashSize int) error {
	buf, err := r.ReadFixed(hashSize)
	if err != nil {
		return fmt.Errorf("failed to read template hash field: %v", err)
	}
	return ng.BasicEntry.parseTemplateHash(buf, hashSize)
}

func (ng *NgTemplate) ParseTemplateName(r FieldReader) error {
	templateName, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read template name field: %v", err)
	}
	return ng.BasicEntry.parseTemplateName(templateName, uint32(len(templateName)), ng.Name())
}

func (ng *NgTemplate) ParseExtraFieldsLen(r FieldReader) (uint32, error) {
	extraFieldsLen, err := r.ReadLen()
	if err != nil {
		return 0, fmt.Errorf("failed to read extra fields length: %v", err)
	}
	return extraFieldsLen, nil
}

func (ng *NgTemplate) ParseFileHash(r FieldReader, hashSize int) error {
	fileHash, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read file hash field: %v", err)
	}
	return ng.parseFileHash(fileHash, uint32(len(fileHash)), hashSize)
}

func (ng *NgTemplate) parseFileHash(fileHash []byte, fileHashLen uint32, hashSize int) error {
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

	ng.FileHash = fileHashField
	return nil
}

func (ng *NgTemplate) parseFilePath(buf []byte, filePathLen uint32) error {
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
	ng.FilePath = filePathField
	return nil
}

func (ng *NgTemplate) ParseFilePath(r FieldReader) error {
	filePath, err := r.ReadLenValue()
	if err != nil {
		return fmt.Errorf("failed to read file path field: %v", err)
	}
	return ng.parseFilePath(filePath, uint32(len(filePath)))
}

func (ng *NgTemplate) ParseExtraFields(r FieldReader, fileHashSize int) error {
	var err error
	// extra fields length
	extraFieldsLen, err := ng.ParseExtraFieldsLen(r)
	if err != nil {
		return fmt.Errorf("failed to read extra fields length: %v", err)
	}
	// File hash
	err = ng.ParseFileHash(r, fileHashSize)
	if err != nil {
		return fmt.Errorf("failed to read file hash field: %v", err)
	}
	// File path
	err = ng.ParseFilePath(r)
	if err != nil {
		return fmt.Errorf("failed to read file path field: %v", err)
	}

	err = ng.ValidateFieldsLen(int(extraFieldsLen))
	if err != nil {
		return fmt.Errorf("failed to validate extra fields length: %v", err)
	}
	return nil
}

func (ng *NgTemplate) ParseEntry(r FieldReader, reservedPcr uint32, templateHashSize, fileHashSize int) error {
	var err error
	err = ng.ParsePCR(r, reservedPcr)
	if err != nil {
		return fmt.Errorf("failed to parse entry: %v", err)
	}
	err = ng.ParseTemplateHash(r, templateHashSize)
	if err != nil {
		return fmt.Errorf("failed to parse entry: %v", err)
	}
	err = ng.ParseTemplateName(r)
	if err != nil {
		return fmt.Errorf("failed to parse entry: %v", err)
	}
	err = ng.ParseExtraFields(r, fileHashSize)
	if err != nil {
		return fmt.Errorf("failed to parse entry: %v", err)
	}
	return nil
}

func (ng *NgTemplate) Size() int {
	size := ng.BasicEntry.Size()
	size += len(ng.FileHash)
	size += len(ng.FilePath)
	size += NgExtraLenFields * lenFieldSize
	return size
}

func (ng *NgTemplate) ValidateFieldsLen(expected int) error {
	actual := ng.Size() - ng.BasicEntry.Size()
	if actual != expected {
		return fmt.Errorf("invalid extra fields length: got %d, want %d", actual, expected)
	}
	return nil
}

func (ng *NgTemplate) MakeTemplateHash(hashAlgo crypto.Hash) ([]byte, error) {
	packedFileHash, err := packHash(ng.FileHash)
	if err != nil {
		return nil, fmt.Errorf("failed to pack file hash field: %v", err)
	}

	packedFilePath, err := packPath(ng.FilePath)
	if err != nil {
		return nil, fmt.Errorf("failed to pack file path field: %v", err)
	}

	packedTemplateEntry := slices.Concat(packedFileHash, packedFilePath)
	hash := hashAlgo.New()
	_, err = hash.Write(packedTemplateEntry)
	if err != nil {
		return nil, fmt.Errorf("failed to compute template hash: %v", err)
	}

	return hash.Sum(nil), nil
}

func (ng *NgTemplate) ValidateEntry(templateHashAlgo crypto.Hash) error {
	computedTemplateHash, err := ng.MakeTemplateHash(templateHashAlgo)
	if err != nil {
		return fmt.Errorf("failed to compute template hash: %v", err)
	}
	if bytes.Compare(computedTemplateHash, ng.TemplateHash) != 0 {
		return fmt.Errorf("template hash mismatch: got %x, want %x", ng.TemplateHash, computedTemplateHash)
	}
	return nil
}

func (ng *NgTemplate) GetTemplateHash() []byte {
	return ng.TemplateHash
}

func (ng *NgTemplate) Name() []byte {
	return []byte("ima-ng")
}

func (ng *NgTemplate) Clear() {
	ng.BasicEntry = BasicEntry{}
	ng.NgExtraFields = NgExtraFields{}
}
