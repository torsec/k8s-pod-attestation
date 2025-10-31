package ima

import (
	"fmt"
	"io"
	"os"
)

const DefaultBinaryPath = "/sys/kernel/security/integrity/ima/binary_runtime_measurements"

const ColonByte = byte(58) // ASCII code for ":"
const NullByte = byte(0)
const DefaultPCRIndex = 10

type MeasurementListType string

const (
	File MeasurementListType = "file"
	Raw  MeasurementListType = "raw"
)

type FieldReader interface {
	ReadLenValue() ([]byte, error)      // reads <len><value>, returns <value>
	ReadLen() (uint32, error)           // reads an independent <len> field
	ReadFixed(size int) ([]byte, error) // reads direct field
}

type MeasurementList struct {
	Type MeasurementListType // complete path to measurement list file or raw content
	Path string              // path to measurement list file
	file *os.File            // file handle to measurement list file
	raw  []byte              // raw content of measurement list
}

func NewMeasurementListFromRaw(raw []byte) *MeasurementList {
	return &MeasurementList{
		Type: Raw,
		raw:  raw,
	}
}

func NewMeasurementListFromFile(path string) *MeasurementList {
	if path == "" {
		path = DefaultBinaryPath
	}
	return &MeasurementList{
		Type: File,
		Path: path,
	}
}

func (ml *MeasurementList) ReadLenValue() ([]byte, error) {
	lenField, err := ml.Read(lenFieldSize)
	if err != nil {
		return nil, fmt.Errorf("failed to read length field from IMA measurement list: %v", err)
	}
	fieldLen, err := parseFieldLen(lenField)
	if err != nil {
		return nil, fmt.Errorf("failed to read length field from IMA measurement list: %v", err)
	}
	return ml.Read(int(fieldLen))
}

func (ml *MeasurementList) ReadLen() (uint32, error) {
	lenField, err := ml.Read(lenFieldSize)
	if err != nil {
		return 0, fmt.Errorf("failed to read length field from IMA measurement list: %v", err)
	}
	fieldLen, err := parseFieldLen(lenField)
	if err != nil {
		return 0, fmt.Errorf("failed to read length field from IMA measurement list: %v", err)
	}
	return fieldLen, nil
}

func (ml *MeasurementList) ReadFixed(size int) ([]byte, error) {
	return ml.Read(size)
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
	return ml.file != nil
}

func (ml *MeasurementList) IsReady() bool {
	switch ml.Type {
	case Raw:
		return ml.raw != nil

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

	ml.file = f
	return nil
}

func (ml *MeasurementList) SetOffset(offset int64) error {
	switch ml.Type {
	case Raw:
		mlLen := int64(len(ml.raw))
		if offset < 0 || offset > mlLen {
			return fmt.Errorf("invalid offset for raw IMA measurement list: %d", offset)
		}
		ml.raw = ml.raw[offset:]
		return nil

	case File:
		if ml.file == nil {
			return fmt.Errorf("failed to read IMA measurement list: file is not open")
		}

		_, err := ml.file.Seek(offset, io.SeekStart)
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

	if ml.file == nil {
		return nil
	}

	err := ml.file.Close()
	if err != nil {
		return fmt.Errorf("failed to close IMA measurement list: %v", err)
	}

	ml.file = nil
	return nil
}

func (ml *MeasurementList) ReadAll() ([]byte, error) {
	switch ml.Type {
	case Raw:
		return ml.raw, nil

	case File:
		if ml.file == nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: file is not open")
		}

		buf, err := io.ReadAll(ml.file)
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
		mlLen := len(ml.raw)
		if mlLen == 0 {
			return nil, io.EOF
		}
		if mlLen < n {
			return nil, fmt.Errorf("failed to read IMA measurement list: not enough data in raw measurement list")
		}
		buf := ml.raw[:n]
		ml.raw = ml.raw[n:]
		return buf, nil

	case File:
		if ml.file == nil {
			return nil, fmt.Errorf("failed to read IMA measurement list: file is not open")
		}

		buf := make([]byte, n)
		_, err := io.ReadAtLeast(ml.file, buf, n)
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
