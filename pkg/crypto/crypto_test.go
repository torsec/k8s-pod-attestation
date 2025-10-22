package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"testing"
)

func TestCorrectHMAC(t *testing.T) {
	key := []byte("supersecretkey")
	msg := []byte("message to protect")

	hmacBytes, err := ComputeHMAC(msg, key, crypto.SHA256)
	if err != nil {
		t.Fatalf("ComputeHMAC failed: %v", err)
	}

	if err := VerifyHMAC(msg, key, hmacBytes, crypto.SHA256); err != nil {
		t.Fatalf("VerifyHMAC failed: %v", err)
	}
}

func TestCorrectHMACAlgoMismatch(t *testing.T) {
	key := []byte("supersecretkey")
	msg := []byte("message to protect")

	hmacBytes, err := ComputeHMAC(msg, key, crypto.SHA256)
	if err != nil {
		t.Fatalf("ComputeHMAC failed: %v", err)
	}

	if err := VerifyHMAC(msg, key, hmacBytes, crypto.SHA1); err == nil {
		t.Fatalf("VerifyHMAC failed: %v", err)
	}
}

func TestIncorrectHMAC(t *testing.T) {
	key := []byte("supersecretkey")
	msg := []byte("message to protect")
	alteredMsg := []byte("message to protect altered")

	hmacBytes, err := ComputeHMAC(msg, key, crypto.SHA256)
	if err != nil {
		t.Fatalf("ComputeHMAC failed: %v", err)
	}

	if err = VerifyHMAC(alteredMsg, key, hmacBytes, crypto.SHA256); err == nil {
		t.Fatalf("VerifyHMAC should have failed for altered message")
	}
}

func TestRSASignVerify(t *testing.T) {
	priv, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("failed to generate RSA key: %v", err)
	}
	msg := []byte("test message")
	sig, err := SignMessage(priv, msg, crypto.SHA256)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if err := VerifyMessage(&priv.PublicKey, msg, sig, crypto.SHA256); err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}

	// PEM encode/decode round-trip
	privPEM, err := EncodePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("EncodePrivateKeyToPEM failed: %v", err)
	}
	decodedPriv, err := DecodePrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("DecodePrivateKeyFromPEM failed: %v", err)
	}
	if _, ok := decodedPriv.(*rsa.PrivateKey); !ok {
		t.Fatalf("decoded key is not RSA: %T", decodedPriv)
	}
}

func TestECDSASignVerify(t *testing.T) {
	priv, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate ECDSA key: %v", err)
	}
	msg := []byte("ecdsa test message")
	sig, err := SignMessage(priv, msg, crypto.SHA256)
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if err := VerifyMessage(&priv.PublicKey, msg, sig, crypto.SHA256); err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}

	// PEM encode/decode round-trip
	privPEM, err := EncodePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("EncodePrivateKeyToPEM failed: %v", err)
	}
	decodedPriv, err := DecodePrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("DecodePrivateKeyFromPEM failed: %v", err)
	}
	if _, ok := decodedPriv.(*ecdsa.PrivateKey); !ok {
		t.Fatalf("decoded key is not ECDSA: %T", decodedPriv)
	}
}

func TestEd25519SignVerify(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		t.Fatalf("failed to generate Ed25519 key: %v", err)
	}
	msg := []byte("ed25519 test message")
	sig, err := SignMessage(priv, msg, crypto.Hash(0))
	if err != nil {
		t.Fatalf("SignMessage failed: %v", err)
	}

	if err := VerifyMessage(pub, msg, sig, crypto.Hash(0)); err != nil {
		t.Fatalf("VerifyMessage failed: %v", err)
	}

	// PEM encode/decode round-trip
	privPEM, err := EncodePrivateKeyToPEM(priv)
	if err != nil {
		t.Fatalf("EncodePrivateKeyToPEM failed: %v", err)
	}
	decodedPriv, err := DecodePrivateKeyFromPEM(privPEM)
	if err != nil {
		t.Fatalf("DecodePrivateKeyFromPEM failed: %v", err)
	}
	if _, ok := decodedPriv.(ed25519.PrivateKey); !ok {
		t.Fatalf("decoded key is not Ed25519: %T", decodedPriv)
	}
}

func TestEncodeDecodePublicKeyPEM(t *testing.T) {
	// Test RSA public key
	rsaPriv, _ := rsa.GenerateKey(rand.Reader, 2048)
	pubPEM, err := EncodePublicKeyToPEM(&rsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("EncodePublicKeyToPEM failed: %v", err)
	}
	pubDecoded, err := DecodePublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("DecodePublicKeyFromPEM failed: %v", err)
	}
	if _, ok := pubDecoded.(*rsa.PublicKey); !ok {
		t.Fatalf("decoded key is not RSA: %T", pubDecoded)
	}

	// Test ECDSA public key
	ecdsaPriv, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	pubPEM, err = EncodePublicKeyToPEM(&ecdsaPriv.PublicKey)
	if err != nil {
		t.Fatalf("EncodePublicKeyToPEM failed: %v", err)
	}
	pubDecoded, err = DecodePublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("DecodePublicKeyFromPEM failed: %v", err)
	}
	if _, ok := pubDecoded.(*ecdsa.PublicKey); !ok {
		t.Fatalf("decoded key is not ECDSA: %T", pubDecoded)
	}

	// Test Ed25519 public key
	edPub, _, _ := ed25519.GenerateKey(rand.Reader)
	pubPEM, err = EncodePublicKeyToPEM(edPub)
	if err != nil {
		t.Fatalf("EncodePublicKeyToPEM failed: %v", err)
	}
	pubDecoded, err = DecodePublicKeyFromPEM(pubPEM)
	if err != nil {
		t.Fatalf("DecodePublicKeyFromPEM failed: %v", err)
	}
	if _, ok := pubDecoded.(ed25519.PublicKey); !ok {
		t.Fatalf("decoded key is not Ed25519: %T", pubDecoded)
	}
}

func TestUnsupportedKeyType(t *testing.T) {
	_, err := SignMessage("unsupported key", []byte("msg"), crypto.SHA256)
	if err == nil {
		t.Fatalf("SignMessage should have failed for unsupported key type")
	}

	_, err = EncodePrivateKeyToPEM("unsupported key")
	if err == nil {
		t.Fatalf("EncodePrivateKeyToPEM should have failed for unsupported key type")
	}

	_, err = EncodePublicKeyToPEM("unsupported key")
	if err == nil {
		t.Fatalf("EncodePublicKeyToPEM should have failed for unsupported key type")
	}
}

func TestGetNonce(t *testing.T) {
	nonce1, err := GetNonce(16)
	if err != nil {
		t.Fatalf("GetNonce failed: %v", err)
	}
	if len(nonce1) != 16 {
		t.Fatalf("GetNonce returned nonce of incorrect length: got %d, want 16", len(nonce1))
	}

	nonce2, err := GetNonce(16)
	if err != nil {
		t.Fatalf("GetNonce failed: %v", err)
	}
	if string(nonce1) == string(nonce2) {
		t.Fatalf("GetNonce returned the same nonce twice")
	}
}
