package model

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func decodePublicKeyFromPEM(publicKeyPEM []byte) (*rsa.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	var rsaPubKey *rsa.PublicKey
	var err error

	switch block.Type {
	case "RSA PUBLIC KEY":
		rsaPubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS1 public key: %v", err)
		}
	case "PUBLIC KEY":
		parsedKey, err := x509.ParsePKIXPublicKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKIX public key: %v", err)
		}
		var ok bool
		rsaPubKey, ok = parsedKey.(*rsa.PublicKey)
		if !ok {
			return nil, fmt.Errorf("not an RSA public key")
		}
	default:
		return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
	}
	return rsaPubKey, nil
}

func TestMarshalEvidenceJSON(t *testing.T) {
	// Test marshaling the evidence to JSON
	evidence, err := NewEvidence(CmwCollectionTypeAttestationEvidence)
	assert.NoError(t, err, "Expected no error when creating new evidence")

	claim, err := NewCmwItem(EatJsonClaimMediaType, []byte("test claim"), EvidenceIndicator)
	assert.NoError(t, err, "Expected no error when creating new claim")

	err = evidence.AddCmwClaim("testClaimKey", claim)
	assert.NoError(t, err, "Expected no error when adding claim to evidence")

	jsonData, err := evidence.ToJSON()
	fmt.Printf("%s\n", jsonData)
	assert.NoError(t, err, "Expected no error when marshaling evidence to JSON")
	assert.NotNil(t, jsonData, "Expected marshaled JSON data to be non-nil")
}

func TestRatsEAR(t *testing.T) {
	measres := []IndividualResult{
		{
			Id:     "file1",
			Result: IrSuccess,
		},
		{
			Id:     "file2",
			Result: IrSuccess,
		},
	}

	eat := &EAT{
		Nonce:   "nonce-abcd",
		Measres: measres,
	}

	eatJSON, err := json.Marshal(eat)
	assert.NoError(t, err, "Expected no error when marshaling EAT to JSON")
	fmt.Printf("%s\n", eatJSON)

	submods := map[string]EARAppraisal{
		"system-boot": {
			Status: SlAffirming,
		},
		"containerization-dependencies": {
			Status: SlAffirming,
		},
		"pod-id:abcdefg": {
			Status: SlAffirming,
		},
	}
	ear, err := NewEAR(eat, "verifier1", submods)
	assert.NoError(t, err, "Expected no error when creating new ear")
	earJSON, err := json.Marshal(ear)
	assert.NoError(t, err, "Expected no error when marshaling EAR to JSON")
	fmt.Printf("%s\n", earJSON)
}

func TestEvidenceToJSON(t *testing.T) {
	evidence, err := NewEvidence(CmwCollectionTypeAttestationEvidence)
	assert.NoError(t, err, "Expected no error when creating new evidence")

	claim, err := NewCmwItem(EatJsonClaimMediaType, []byte("test claim"), EvidenceIndicator)
	assert.NoError(t, err, "Expected no error when creating new claim")

	err = evidence.AddCmwClaim("testClaimKey", claim)
	assert.NoError(t, err, "Expected no error when adding claim to evidence")
	jsonData, err := evidence.ToJSON()
	assert.NoError(t, err, "Expected no error when marshaling evidence to JSON")
	assert.NotNil(t, jsonData, "Expected marshaled JSON data to be non-nil")
}
