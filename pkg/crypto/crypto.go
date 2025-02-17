package crypto

import (
	"crypto"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/pem"
	"fmt"
)

// Helper function to verify HMAC
func VerifyHMAC(message, ephemeralKey, providedHMAC []byte) error {
	h := hmac.New(sha256.New, ephemeralKey)
	h.Write(message)
	expectedHMAC := h.Sum(nil)

	if !hmac.Equal(expectedHMAC, providedHMAC) {
		return fmt.Errorf("HMAC verification failed")
	}

	return nil
}

func DecodePublicKeyFromPEM(publicKeyPEM string) (*rsa.PublicKey, error) {
	block, _ := pem.Decode([]byte(publicKeyPEM))
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

// Generate a cryptographically secure random symmetric key of the specified size in bytes
func GenerateEphemeralKey(size int) ([]byte, error) {
	if size <= 0 {
		return nil, fmt.Errorf("key size must be greater than 0")
	}

	key := make([]byte, size)
	_, err := rand.Read(key)
	if err != nil {
		return nil, fmt.Errorf("failed to generate random key: %v", err)
	}
	return key, nil
}

// Helper function to encode the public key to PEM format (for printing)
func EncodePublicKeyToPEM(pubKey crypto.PublicKey) string {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return ""
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY", // Use "PUBLIC KEY" for X.509 encoded keys
		Bytes: pubASN1,
	})
	return string(pubPEM)
}

// generateNonce creates a random nonce of specified byte length
func GenerateHexNonce(size int) (string, error) {
	nonce := make([]byte, size)

	// Fill the byte slice with random data
	_, err := rand.Read(nonce)
	if err != nil {
		return "", fmt.Errorf("error generating nonce: %v", err)
	}

	// Return the nonce as a hexadecimal string
	return hex.EncodeToString(nonce), nil
}
