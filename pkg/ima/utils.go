package ima

import (
	"bytes"
	"crypto"
	"encoding/binary"
	"fmt"
)

const lenFieldSize = 4 // size of field containing length of variable-length fields
const pcrSize = 4

// parseFieldLen parses a length field from a byte buffer and returns the length as uint32.
func parseFieldLen(field []byte) (uint32, error) {
	fieldSize := len(field)
	if fieldSize != lenFieldSize {
		return 0, fmt.Errorf("invalid length field size: got %d, want %d", fieldSize, lenFieldSize)
	}
	fieldLen := binary.LittleEndian.Uint32(field)
	return fieldLen, nil
}

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

func isValidFileHashAlgo(hashAlgo []byte) bool {
	switch string(hashAlgo) {
	case "sha1", "sha256", "sha384", "sha512", "md5":
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
