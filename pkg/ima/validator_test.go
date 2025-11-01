package ima

import (
	"crypto"
	"github.com/stretchr/testify/assert"
	"io"
	"os"
	"testing"
)

func TestValidator_MeasurementListAttestation_raw(t *testing.T) {
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
		aggregate:        make([]byte, crypto.SHA1.Size()),
		PcrIndex:         DefaultPCRIndex,
		TemplateHashAlgo: crypto.SHA1,
		FileHashAlgo:     crypto.SHA256,
	}
	v := NewCgPathValidator(ml, i, nil)

	expected := []byte{
		0xDF, 0x48, 0x52, 0xD4, 0xF3, 0xCB, 0x10, 0xED,
		0x4C, 0x9A, 0x1E, 0x26, 0x6C, 0x0D, 0x7A, 0x66,
		0x4D, 0xF0, 0xCA, 0xC4,
	}

	err = v.MeasurementListAttestation(expected)
	assert.NoError(t, err)
}

func TestValidator_MeasurementListAttestation_file(t *testing.T) {
	ml := &MeasurementList{
		Type: File,
		Path: "../../tests/bin_ima",
	}
	err := ml.Open(0)
	assert.NoError(t, err)

	i := &Integrity{
		attested:         0,
		aggregate:        make([]byte, crypto.SHA1.Size()),
		PcrIndex:         DefaultPCRIndex,
		TemplateHashAlgo: crypto.SHA1,
		FileHashAlgo:     crypto.SHA256,
	}
	h := NewCgPathValidator(ml, i, nil)

	expected := []byte{
		0xDF, 0x48, 0x52, 0xD4, 0xF3, 0xCB, 0x10, 0xED,
		0x4C, 0x9A, 0x1E, 0x26, 0x6C, 0x0D, 0x7A, 0x66,
		0x4D, 0xF0, 0xCA, 0xC4,
	}

	err = h.MeasurementListAttestation(expected)
	assert.NoError(t, err)
}

func TestValidator_MeasurementListAttestation_target(t *testing.T) {
	ml := &MeasurementList{
		Type: File,
		Path: "../../tests/bin_ima",
	}
	err := ml.Open(0)
	assert.NoError(t, err)

	i := &Integrity{
		attested:         0,
		aggregate:        make([]byte, crypto.SHA1.Size()),
		PcrIndex:         DefaultPCRIndex,
		TemplateHashAlgo: crypto.SHA1,
		FileHashAlgo:     crypto.SHA256,
	}
	target, err := NewCGPathTarget([]byte("c439ca84_e4c4_42ab_a0c6_298c8067be39"), Containerd)
	assert.NoError(t, err)

	v := NewCgPathValidator(ml, i, target)

	expected := []byte{
		0xDF, 0x48, 0x52, 0xD4, 0xF3, 0xCB, 0x10, 0xED,
		0x4C, 0x9A, 0x1E, 0x26, 0x6C, 0x0D, 0x7A, 0x66,
		0x4D, 0xF0, 0xCA, 0xC4,
	}

	err = v.MeasurementListAttestation(expected)
	assert.NoError(t, err)

	assert.Equal(t, len(v.Target.GetMatches().Measurements[Pod]), 44)
	assert.Equal(t, len(v.Target.GetMatches().Measurements[ContainerRuntime]), 7)
}

func TestValidator_MeasurementListAttestation_ng(t *testing.T) {
	ml := &MeasurementList{
		Type: File,
		Path: "../../tests/ima_ng",
	}
	err := ml.Open(0)
	assert.NoError(t, err)

	i := &Integrity{
		attested:         0,
		aggregate:        make([]byte, crypto.SHA1.Size()),
		PcrIndex:         DefaultPCRIndex,
		TemplateHashAlgo: crypto.SHA1,
		FileHashAlgo:     crypto.SHA256,
	}

	v := NewNgValidator(ml, i, nil)
	expected := []byte{
		0xDA, 0x7C, 0xE8, 0x2C, 0x00, 0xA5, 0x52, 0x64,
		0x83, 0x39, 0x10, 0x51, 0xF3, 0xFB, 0x73, 0x6F,
		0xCD, 0xE2, 0x08, 0xCA,
	}

	err = v.MeasurementListAttestation(expected)
	assert.NoError(t, err)
}

func TestValidator_MeasurementListAttestation_cgpath_partialAttestation(t *testing.T) {
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
		aggregate:        make([]byte, crypto.SHA1.Size()),
		PcrIndex:         DefaultPCRIndex,
		TemplateHashAlgo: crypto.SHA1,
		FileHashAlgo:     crypto.SHA256,
	}

	v := NewCgPathValidator(ml, i, nil)
	expected := []byte{
		0xfb, 0x9d, 0xb2, 0x68, 0x28, 0x71, 0xca, 0x11,
		0x64, 0x70, 0x28, 0x3a, 0x8d, 0xc4, 0x50, 0x9a,
		0xe6, 0xa8, 0x04, 0x3d,
	}
	lastEntryTemplateHash := []byte{
		0xf1, 0x8e, 0xf9, 0xf9, 0x8c, 0xf0, 0x3b, 0x46,
		0xbe, 0xd1, 0x95, 0x50, 0x12, 0x26, 0x91, 0x85,
		0x40, 0xcf, 0xc2, 0x3e,
	}

	err = v.MeasurementListAttestation(expected)

	assert.NoError(t, err)
	assert.Equal(t, v.Entry.GetTemplateHash(), lastEntryTemplateHash)

	expected = []byte{
		0xDF, 0x48, 0x52, 0xD4, 0xF3, 0xCB, 0x10, 0xED,
		0x4C, 0x9A, 0x1E, 0x26, 0x6C, 0x0D, 0x7A, 0x66,
		0x4D, 0xF0, 0xCA, 0xC4,
	}

	err = v.MeasurementListAttestation(expected)
	assert.NoError(t, err)
}
