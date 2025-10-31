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
		raw:  raw,
	}
	i := &Integrity{
		attested:         0,
		aggregate:        make([]byte, 20),
		pcrIndex:         DefaultPCRIndex,
		TemplateHashAlgo: crypto.SHA1,
		FileHashAlgo:     crypto.SHA256,
	}
	h := NewHelper(ml, i, nil)

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
		pcrIndex:         DefaultPCRIndex,
		TemplateHashAlgo: crypto.SHA1,
		FileHashAlgo:     crypto.SHA256,
	}
	h := NewHelper(ml, i, nil)

	expected := []byte{
		0xDF, 0x48, 0x52, 0xD4, 0xF3, 0xCB, 0x10, 0xED,
		0x4C, 0x9A, 0x1E, 0x26, 0x6C, 0x0D, 0x7A, 0x66,
		0x4D, 0xF0, 0xCA, 0xC4,
	}

	err = h.MeasurementListAttestation(expected)
	assert.NoError(t, err)
}

func TestHelper_MeasurementListAttestation_target(t *testing.T) {
	ml := &MeasurementList{
		Type: File,
		Path: "../../tests/bin_ima",
	}
	err := ml.Open(0)
	assert.NoError(t, err)

	i := &Integrity{
		attested:         0,
		aggregate:        make([]byte, 20),
		pcrIndex:         DefaultPCRIndex,
		TemplateHashAlgo: crypto.SHA1,
		FileHashAlgo:     crypto.SHA256,
	}
	target, err := NewTarget([]byte("c439ca84_e4c4_42ab_a0c6_298c8067be39"), Containerd)
	assert.NoError(t, err)

	h := NewHelper(ml, i, target)

	expected := []byte{
		0xDF, 0x48, 0x52, 0xD4, 0xF3, 0xCB, 0x10, 0xED,
		0x4C, 0x9A, 0x1E, 0x26, 0x6C, 0x0D, 0x7A, 0x66,
		0x4D, 0xF0, 0xCA, 0xC4,
	}

	err = h.MeasurementListAttestation(expected)
	assert.NoError(t, err)

	assert.Equal(t, len(h.Entry.GetTarget().Matches[PodMeasurement]), 44)
	assert.Equal(t, len(h.Entry.GetTarget().Matches[ContainerRuntimeMeasurement]), 7)
}
