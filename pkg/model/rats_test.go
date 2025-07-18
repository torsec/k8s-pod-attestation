package model

import (
	"encoding/json"
	"fmt"
	"github.com/stretchr/testify/assert"
	"testing"
)

func TestMarshalEvidenceJSON(t *testing.T) {
	// Test marshaling the evidence to JSON
	evidence, err := NewEvidence()
	assert.NoError(t, err, "Expected no error when creating new evidence")

	claim, err := NewClaim(EatJsonClaimMediaType, []byte("test claim"))
	assert.NoError(t, err, "Expected no error when creating new claim")

	err = evidence.AddClaim("testClaimKey", claim)
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
