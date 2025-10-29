package ima

import (
	"crypto"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"testing"
)

func TestHelper_MeasurementListAttestation_raw(t *testing.T) {
	f, err := os.Open("../../tests/bin_ima")
	assert.NoError(t, err)
	raw, err := io.ReadAll(f)
	assert.NoError(t, err)
	err = f.Close()
	assert.NoError(t, err)

	ml := &MeasurementList{
		Type: Raw,
		Raw:  raw,
	}
	i := &Integrity{
		attested:         0,
		aggregate:        make([]byte, 20),
		pcrIndex:         10,
		TemplateHashAlgo: crypto.SHA1,
		FileHashAlgo:     crypto.SHA256,
	}
	h := NewHelper(ml, i)

	expected := []byte{
		0xDF, 0x48, 0x52, 0xD4, 0xF3, 0xCB, 0x10, 0xED,
		0x4C, 0x9A, 0x1E, 0x26, 0x6C, 0x0D, 0x7A, 0x66,
		0x4D, 0xF0, 0xCA, 0xC4,
	}

	err = h.MeasurementListAttestation(expected)
	assert.NoError(t, err)
}

func TestHelper_MeasurementListAttestation_file(t *testing.T) {
	ml := &MeasurementList{
		Type: File,
		Path: "../../tests/bin_ima",
	}
	err := ml.Open(0)
	assert.NoError(t, err)

	i := &Integrity{
		attested:         0,
		aggregate:        make([]byte, 20),
		pcrIndex:         10,
		TemplateHashAlgo: crypto.SHA1,
		FileHashAlgo:     crypto.SHA256,
	}
	h := NewHelper(ml, i)

	expected := []byte{
		0xDF, 0x48, 0x52, 0xD4, 0xF3, 0xCB, 0x10, 0xED,
		0x4C, 0x9A, 0x1E, 0x26, 0x6C, 0x0D, 0x7A, 0x66,
		0x4D, 0xF0, 0xCA, 0xC4,
	}

	err = h.MeasurementListAttestation(expected)
	assert.NoError(t, err)
}
