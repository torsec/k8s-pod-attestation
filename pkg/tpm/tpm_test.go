package tpm

import (
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestKeyTypeFromString(t *testing.T) {
	kt, err := KeyTypeFromString("RSA")
	assert.NoError(t, err)
	assert.Equal(t, RSA, kt)
}
