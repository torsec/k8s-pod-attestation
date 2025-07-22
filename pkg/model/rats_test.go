package model

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
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

	claim, err := NewCmwItem(EatJsonClaimMediaType, []byte("test claim"))
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

func TestRatsAttestationResultFromJWT(t *testing.T) {
	jwtToken := "eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJjbXciOiJleUpmWDJOdGQyTmZkQ0k2SW5SaFp6cGhkSFJsYzNSaGRHbHZiaTVqYjIwc01qQXlOVHBoZEhSbGMzUmhkR2x2YmkxeVpYTjFiSFFpTENKbFlYSWlPbHNpWVhCd2JHbGpZWFJwYjI0dlpXRjBLMnAzZENJc0ltVjVTbXhaV0ZKbVkwaEtkbHB0YkhOYVUwazJTVzVTYUZwNmNHNWhXRkp2WkZkSmRWa3lPWFJNUkVsM1RXcE5ObVJ0Vm5sWlYyeDZZakkwZGxwWFJubEphWGRwWVZkR01FbHFiM2hPZWxWNVQxUk5NazVxU1hsTVEwb3lXbGhLY0ZwdGJHeGphVEZ3V2tNeGMxbFhTbXhpUTBrMlNXNWFiR050YkcxaFYxWjVURlJuTUU1cVdtMVphbEpwVGxSUmRHRklaekZsUkd0cFRFTktiRmxZU1hWamJVWXpURmRXTW1GWFVteGliVTVzU1dwdmFWcFliRXRrVjBsNVRsZHdZVlV3YXpKVFYzQkRZa1UxTm1KSGNFOWxhMncxVkZkd2MyRnJOWEZWV0d4UFZrVkdjRlJGVGt0a1JuQllVbTV3YW1KV1dqWlRWM0IzV1cxV05WTnVRbUZSTUdzeVUxZHJOVTFYVFhwVFdGcGFZbGQ0TVZSRVNrOWtiVXAxVlcxb2FGWjZWbk5aTWpGU1pFZE5lV0ZJUW1sVmVrWTFXa1pqTVdGcmVGbFhXR3hLWVZoa2NGa3lNVmRsYlZKWVpVUkNTbUZ0T1RSYWJFNDBUakJzZEdKSGRFcGhiVGx3VkVSSk5XUXlVa1JQVjNCcFlsZDBNbGRYTVhOa1ZYZDVaVWhhYVUwd1NuQlhWbVJQWTJ0c2NHUXliR3BpVmxvMldrWmtORTFGYkhGaU0yaHRWVE5uTTFOWE1YTmhNR3h4WWpKc1RVMXFiRE5hUlUwMVlXMUtkR0V6V2xwaVYzZ3hWRVJLVDJGSFNraGlSM0JwWlZWc2VsTlhOVXRpUjAxNlZtNU9hMUV3YXpKVVZtZDNZekpXTlZOdVFtRlJNR3N5VTFkck5XUnRUa2xWV0ZwYVRXcFdkMVJFU2t0alIwcHdUMWhrYVUwd2IzZFpiR1JIWkRCc2NHUXliR3BpVmxvMldrWmtORTFGYkhGaU0yaHRWVE5uTTFOWE1YTmhNR3h4WWpKc1RVMXFiRE5hUlUwMVlXMUtkR0V6V2xwaVYzZ3hWRVJLUzJGSFNuUlZhazVvVmpGSmQxbFZUa3BqTUd4MVUyMTRhazB4V25wYVJVNUtUbXN4V1UxSVRteGxWWEIzVjJ0T1NrNXJiSEJQVkVacVRUQnNNbGRYTVhOa1ZYZDZWbTVXYWxJeWVIVmFWMnhLWXpCc2RWTnRlR3BOTVZwNldrVk9TazVyTVZsTlNFNXNaVlZ3ZDFkclRrcE9hMnh3VDFkc2FGWjZVakpYVnpWWFpXMVdXRk51V214Uk1HeDZVMWMxUzJKSFRYcFdiazVyVVRCck1sUldaM2RqTWxZMVUyNUNZVkV3YXpKVFYyczFaREZzV1ZadWNHRlZNR3g2VTFjMVMySkhUWHBXYms1clVUQnJNbFJXWjNkak1sWTFVMjVDWVZFd2F6SlRWMnMxWXpKR1dGTllXbWxTTVVZd1dXeG9WMlZ0U2tSTlZGSlFVa1p3YlZSdGNGSmtWMDE1VDBoV1RsVXdiSHBUVnpWTFlrZE5lbFp1VG10Uk1Hc3lWR3RuZDJNeVZqVlRia0poVVRCck1sTlhhelZrVjBsNlZWaFNhbUpzV2pGVVJtUlhaRmRTU1ZOcVZrcGhXR1J3V1RJeFYyVnRVbGhsUkVKS1lXMDVObHBzVGpST01HeDBZa2QwU21GdE9YQlVSRXBMWTBkS2NFOVhiR3RYUlRReFYxY3dOVTVGYkhCa01teHFZbFphTmxwR1pEUk5SV3h4WWpOc2JWWnFSVFZKYVhkcFl6TldhV0pYT1d0amVVazJaWGxLYW1JeU5UQlpWMngxV2xoS2NHVnRSakJoVnpsMVRGZFNiR05IVm5WYVIxWjFXVEpzYkdONVNUWmxlVXBzV1ZoSmRXTXpVbWhrU0ZaNlNXcHZlV1pUZDJsalJ6bHJURmRzYTA5cVdUTk9SRmt4VFhwYWFFeFhUWGhPZWxWMFRrZGFhRmxwTVdoYVJHc3hURmRHYkU5RVdYaE9WRTVyVGxSV2EwNVRTVFpsZVVwc1dWaEpkV016VW1oa1NGWjZTV3B2TlU1dU1ITkpiazQxWXpOU2JHSlRNV2xpTWprd1NXcHdOMGx0Vm1oamFUVjZaRWRHTUdSWVRXbFBha281Wmxnd0lpdzRYWDA9IiwiZXhwIjoxNzUyOTM2OTIyLCJpc3MiOiJSQS1FbmdpbmUiLCJuYmYiOjE3NTI5MzY2MjJ9.VDmOFvykgvZCpqVR9omCEiIepaA2qE1JaZV40DmtrF9az8ptlRPUKf7SXXfPf3f1bD3xeD7k3Zh56ApUC-bjMrxZWoy31HFZk9NUBcLY-TWu3l-5HcbnTBT9j_2PxfXTxfXk7XHDbn_WmSYAobvqaf7lsNrjpi1DNWWVk92SHLWPNo0dIv3LG0AsNNhvdHL_GeYsvQO4_5zDOP0FX6cBPwhhcJBECqzmjMQ-e4dN53Bhd_qBPLVpVLNSSrWU-mFJjPWIes_LYKEDrE3Q-Dl_udx0IQz-gmxj0HuZIBOonQoEfSU4tCbyWTKr3XIhLkwAockIT_XLlfZJ_R2Ow9dhGQ"
	pubKeyPem := "-----BEGIN PUBLIC KEY-----\nMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoi/38EDObItiLd1Q8Cy\nXsPaHjOreYqVJYEO4NfCZR2H01LXrdj/LcpyrB1rKBc4UWI8lroSdhjMJxC62372\nWvDk9cD5k+iyPwdM+EggpiRfEmHWF3zob8junyWHW6JInf0+AGhbKgBfMXo9PvAn\nr5CVeqp2BrstdZtrWVRuQAKip9c7hl+mHODkE5yb0InHyRe5WWr5P7wtXtAPM6SO\n8dVk/QWXdsB9rsb+Ejy4LHSIUpHUOZO8LvGD1rVLO82H4EUXKBFeiOEJjly4HOkv\nmFe/c/Cma1pM+702X6ULf0/BIMJkWzD3INdLtk8FE8rIxrrMSnDtmWw9BgGdsDgk\npQIDAQAB\n-----END PUBLIC KEY-----\n"
	pubKey, err := decodePublicKeyFromPEM([]byte(pubKeyPem))
	assert.NoError(t, err)
	ar, err := AttestationResultFromJWT(jwtToken, jwt.SigningMethodRS256, pubKey)
	assert.NoError(t, err)
	jsonResult, err := ar.ToJSON()
	assert.NoError(t, err)
	fmt.Println(string(jsonResult))
}
