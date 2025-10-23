package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/hmac"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/asn1"
	"encoding/pem"
	"fmt"
	x509ext "github.com/google/go-attestation/x509"
	"math/big"
)

type TPMVendor struct {
	VendorId string `json:"vendorId,omitempty"`
	Name     string `json:"vendorName"`
	TCGId    string `json:"TCGId"`
}

type ECDSASignature struct {
	R *big.Int
	S *big.Int
}

func NewECDSASignature(r, s *big.Int) *ECDSASignature {
	return &ECDSASignature{R: r, S: s}
}

func (r *ECDSASignature) ToASN1() ([]byte, error) {
	return asn1.Marshal(*r)
}

func ECDSASignatureFromASN1(asn1Bytes []byte) (*ECDSASignature, error) {
	var sig ECDSASignature
	_, err := asn1.Unmarshal(asn1Bytes, &sig)
	if err != nil {
		return nil, fmt.Errorf("failed to parse ECDSA signature: %w", err)
	}
	return &sig, nil
}

// VerifyHMAC checks if the provided HMAC matches the computed HMAC for the given message and key.
func VerifyHMAC(message, key, providedHMAC []byte, hashAlgo crypto.Hash) error {
	if !hashAlgo.Available() {
		return fmt.Errorf("hash algorithm %v is not available", hashAlgo)
	}
	h := hmac.New(hashAlgo.New, key)
	h.Write(message)
	expectedHMAC := h.Sum(nil)

	if !hmac.Equal(expectedHMAC, providedHMAC) {
		return fmt.Errorf("HMAC verification failed")
	}

	return nil
}

// ComputeHMAC computes the HMAC of a message using the given key and hash algorithm.
func ComputeHMAC(message, key []byte, hashAlgo crypto.Hash) ([]byte, error) {
	if !hashAlgo.Available() {
		return nil, fmt.Errorf("hash algorithm %v is not available", hashAlgo)
	}

	h := hmac.New(hashAlgo.New, key)
	h.Write(message)
	return h.Sum(nil), nil
}

// DecodePublicKeyFromPEM decodes a PEM-encoded public key of any supported type
// (RSA, ECDSA, or Ed25519) and returns it as crypto.PublicKey.
func DecodePublicKeyFromPEM(publicKeyPEM []byte) (crypto.PublicKey, error) {
	block, _ := pem.Decode(publicKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing public key")
	}

	var pubKey crypto.PublicKey
	var err error

	switch block.Type {
	case "RSA PUBLIC KEY":
		pubKey, err = x509.ParsePKCS1PublicKey(block.Bytes)
	case "PUBLIC KEY":
		pubKey, err = x509.ParsePKIXPublicKey(block.Bytes)
	default:
		return nil, fmt.Errorf("unsupported public key type: %s", block.Type)
	}

	if err != nil {
		return nil, fmt.Errorf("failed to parse public key: %v", err)
	}

	// Type-check to ensure it’s one of the supported kinds
	switch pubKey.(type) {
	case *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey:
		return pubKey, nil
	default:
		return nil, fmt.Errorf("unsupported public key algorithm: %T", pubKey)
	}
}

// SignMessage signs `message` using the provided `privKey` and `hashAlgo`.
// Supported key types: *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey.
// For Ed25519, the hash algorithm is ignored (it signs the raw message).
func SignMessage(privateKey crypto.PrivateKey, message []byte, hashAlgo crypto.Hash) ([]byte, error) {
	var hashed []byte

	// Hash the message unless the algorithm doesn't require it (Ed25519)
	if hashAlgo != crypto.Hash(0) {
		if !hashAlgo.Available() {
			return nil, fmt.Errorf("hash algorithm %v not available", hashAlgo)
		}
		h := hashAlgo.New()
		h.Write(message)
		hashed = h.Sum(nil)
	} else {
		hashed = message
	}

	switch key := privateKey.(type) {

	case *rsa.PrivateKey:
		// RSA always needs a hash (cannot use hashAlgo=0)
		if hashAlgo == crypto.Hash(0) {
			return nil, fmt.Errorf("RSA requires a hash algorithm")
		}
		return rsa.SignPKCS1v15(rand.Reader, key, hashAlgo, hashed)

	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, key, hashed)
		if err != nil {
			return nil, fmt.Errorf("failed to sign message with ECDSA: %v", err)
		}
		return NewECDSASignature(r, s).ToASN1()

	case ed25519.PrivateKey:
		// Hash ignored, Ed25519 signs the message directly
		return ed25519.Sign(key, message), nil

	default:
		return nil, fmt.Errorf("unsupported private key type: %T", key)
	}
}

// VerifyMessage verifies a digital signature created by SignMessage.
// Supported key types: *rsa.PublicKey, *ecdsa.PublicKey, ed25519.PublicKey.
// For Ed25519, the hash algorithm is ignored (it verifies the raw message).
func VerifyMessage(publicKey crypto.PublicKey, message, signature []byte, hashAlgo crypto.Hash) error {
	var hashed []byte

	// Hash message if required
	if hashAlgo != crypto.Hash(0) {
		if !hashAlgo.Available() {
			return fmt.Errorf("hash algorithm %v not available", hashAlgo)
		}
		h := hashAlgo.New()
		h.Write(message)
		hashed = h.Sum(nil)
	} else {
		hashed = message
	}

	switch key := publicKey.(type) {

	case *rsa.PublicKey:
		// RSA expects hashed input
		if hashAlgo == crypto.Hash(0) {
			return fmt.Errorf("RSA requires a hash algorithm")
		}
		return rsa.VerifyPKCS1v15(key, hashAlgo, hashed, signature)

	case *ecdsa.PublicKey:
		var sig ecdsaSignature
		if _, err := asn1.Unmarshal(signature, &sig); err != nil {
			return fmt.Errorf("failed to unmarshal ECDSA signature: %v", err)
		}

		if !ecdsa.Verify(key, hashed, sig.R, sig.S) {
			return fmt.Errorf("invalid ECDSA signature")
		}
		return nil

	case ed25519.PublicKey:
		// Hash ignored, verify directly
		if !ed25519.Verify(key, message, signature) {
			return fmt.Errorf("invalid Ed25519 signature")
		}
		return nil

	default:
		return fmt.Errorf("unsupported public key type: %T", key)
	}
}

func Hash(message []byte, hashAlgo crypto.Hash) ([]byte, error) {
	hash := hashAlgo.New()
	_, err := hash.Write(message)
	if err != nil {
		return nil, fmt.Errorf("failed to compute hash: %v", err)
	}
	digest := hash.Sum(nil)
	return digest, nil
}

// GenerateEphemeralKey generates a cryptographically secure random symmetric key of the specified size in bytes
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

// EncodePublicKeyToPEM helper function to encode the public key to PEM format (for printing)
func EncodePublicKeyToPEM(pubKey crypto.PublicKey) ([]byte, error) {
	pubASN1, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal public key: %v", err)
	}
	pubPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: pubASN1,
	})
	return pubPEM, nil
}

// GetNonce creates a random nonce of specified byte length
func GetNonce(size int) ([]byte, error) {
	nonce := make([]byte, size)

	_, err := rand.Read(nonce)
	if err != nil {
		return nil, fmt.Errorf("error generating nonce: %v", err)
	}

	return nonce, nil
}

// EncodePrivateKeyToPEM encodes a crypto.PrivateKey into a PEM block.
// Supports *rsa.PrivateKey, *ecdsa.PrivateKey, and ed25519.PrivateKey.
func EncodePrivateKeyToPEM(privKey crypto.PrivateKey) ([]byte, error) {
	var privBytes []byte
	var blockType string
	var err error

	switch key := privKey.(type) {
	case *rsa.PrivateKey:
		// PKCS#1
		privBytes = x509.MarshalPKCS1PrivateKey(key)
		blockType = "RSA PRIVATE KEY"

	case *ecdsa.PrivateKey:
		// EC Private Key
		privBytes, err = x509.MarshalECPrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal ECDSA private key: %v", err)
		}
		blockType = "EC PRIVATE KEY"

	case ed25519.PrivateKey:
		// PKCS#8 format
		privBytes, err = x509.MarshalPKCS8PrivateKey(key)
		if err != nil {
			return nil, fmt.Errorf("failed to marshal Ed25519 private key: %v", err)
		}
		blockType = "PRIVATE KEY"

	default:
		return nil, fmt.Errorf("unsupported private key type: %T", privKey)
	}

	privPEM := pem.EncodeToMemory(&pem.Block{
		Type:  blockType,
		Bytes: privBytes,
	})
	return privPEM, nil
}

// DecodePrivateKeyFromPEM decodes a PEM-encoded private key.
// Supports RSA, ECDSA, and Ed25519 keys in PKCS#1, PKCS#8 formats.
func DecodePrivateKeyFromPEM(privateKeyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(privateKeyPEM)
	if block == nil {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	switch block.Type {
	case "RSA PRIVATE KEY":
		return x509.ParsePKCS1PrivateKey(block.Bytes)
	case "EC PRIVATE KEY":
		return x509.ParseECPrivateKey(block.Bytes)
	case "PRIVATE KEY":
		// PKCS#8 format (can contain RSA, ECDSA, Ed25519)
		key, err := x509.ParsePKCS8PrivateKey(block.Bytes)
		if err != nil {
			return nil, fmt.Errorf("failed to parse PKCS#8 private key: %v", err)
		}
		switch key := key.(type) {
		case *rsa.PrivateKey, *ecdsa.PrivateKey, ed25519.PrivateKey:
			return key, nil
		default:
			return nil, fmt.Errorf("unsupported private key type in PKCS#8: %T", key)
		}
	default:
		return nil, fmt.Errorf("unsupported key type: %s", block.Type)
	}
}

// LoadCertificateFromPEM loads a certificate from a PEM string
func LoadCertificateFromPEM(pemCert []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(pemCert)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing the certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %v", err)
	}
	return cert, nil
}

// handleTPMSubjectAltName processes the subjectAltName extension to mark it as handled
func handleTPMSubjectAltName(cert *x509.Certificate, tpmVendors []TPMVendor) error {
	for _, ext := range cert.Extensions {
		if ext.Id.Equal([]int{2, 5, 29, 17}) { // OID for subjectAltName
			subjectAltName, err := x509ext.ParseSubjectAltName(ext)
			if err != nil {
				return err
			}

			// check if Certificate Vendor is a TCG valid one
			TCGVendorId := (subjectAltName.DirectoryNames[0].Names[0].Value).(string)
			var foundTPMVendor *TPMVendor

			for _, tpmVendor := range tpmVendors {
				if tpmVendor.TCGId == TCGVendorId {
					foundTPMVendor = &tpmVendor
				}
			}

			if foundTPMVendor == nil {
				return fmt.Errorf("TPM Vendor Not Found")
			}

			// TODO implement checks on platform model and firmware version
			//TPMModel := subjectAltName.DirectoryNames[0].Names[1]
			//TPMVersion := subjectAltName.DirectoryNames[0].Names[2]

			// Remove from UnhandledCriticalExtensions if it's the SAN extension
			for i, unhandledExt := range cert.UnhandledCriticalExtensions {
				if unhandledExt.Equal(ext.Id) {
					// Remove the SAN extension from UnhandledCriticalExtensions
					cert.UnhandledCriticalExtensions = append(cert.UnhandledCriticalExtensions[:i], cert.UnhandledCriticalExtensions[i+1:]...)
					break
				}
			}
			return nil
		}
	}
	return fmt.Errorf("SubjectAltName extension not found")
}

// VerifyEKCertificateChain verifies the provided certificate chain from PEM strings
func VerifyEKCertificateChain(ekCert, intermediateCACert, rootCACert *x509.Certificate, tpmVendors []TPMVendor) error {
	roots := x509.NewCertPool()
	roots.AddCert(rootCACert)

	intermediates := x509.NewCertPool()
	intermediates.AddCert(intermediateCACert)

	opts := x509.VerifyOptions{
		KeyUsages:     []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
		Roots:         roots,
		Intermediates: intermediates,
	}

	err := handleTPMSubjectAltName(ekCert, tpmVendors)
	if err != nil {
		return fmt.Errorf("EK Certificate verification failed: %v", err)
	}

	if _, err := ekCert.Verify(opts); err != nil {
		return fmt.Errorf("EK Certificate verification failed: %v", err)
	}
	return nil
}

// VerifyIntermediateCaCertificateChain verifies the provided certificate chain
func VerifyIntermediateCaCertificateChain(intermediateCACert, rootCACert *x509.Certificate) error {
	roots := x509.NewCertPool()
	roots.AddCert(rootCACert)

	opts := x509.VerifyOptions{
		Roots: roots,
	}

	if _, err := intermediateCACert.Verify(opts); err != nil {
		return fmt.Errorf("TPM Intermediate CA Certificate verification failed: %v", err)
	}
	return nil
}
