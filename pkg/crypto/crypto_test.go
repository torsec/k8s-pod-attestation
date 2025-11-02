package crypto

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"github.com/stretchr/testify/assert"
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

func TestLoadCertificateFromPEM(t *testing.T) {
	rootCaPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIEEDCCAnigAwIBAgIULlUfO3DQH6+jBto2jCHi2ZPV/ckwDQYJKoZIhvcNAQEL\nBQAwHzEdMBsGA1UEAxMUc3d0cG0tbG9jYWxjYS1yb290Y2EwIBcNMjUxMDIwMTQy\nMzExWhgPOTk5OTEyMzEyMzU5NTlaMB8xHTAbBgNVBAMTFHN3dHBtLWxvY2FsY2Et\ncm9vdGNhMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA4slS3pbbI+8E\nRwDKbHybjX6ghEsrIsek4NzLZZ4VknULK4LzY4+h1YA1ZGjJdyS3Ho+C718Tg5I9\nYuowRloj3ImPXfy1m66CVGHFU5xwe28SqTMKOWbMKXQLCd1K1+8uyunaAFgdfn81\nJSnX+n8ckIuEC90FRKAW4kEsmPINFZ2K/5s4gt+QxKnyBrbbusclOh4dE4R+y9Be\nph4SNX1OVahd19LFCmYM/At2D1ttVHloI3dCrSmKKsKJXItEVubAktsG2YlPFCk4\nKNtE0+NqbPHaR/SQDM12y+o6+6GebgYMV991hpOnKc0Tx0+VxVsmn+AUl4aMmM5P\nrcTooR1Sdh5J4ypMNkrvcztTK0sfBKV6eOuYCkHb7AYZwV0bSBQ87Ngyis34e2Ud\nYc9QV/CSMKK3NtzrPO/MDhNXBmZ+sRXxy+Z4/Zo+OixFPtE2NOJw0VN34TT7VZd7\nK0X83/7gF3T+yFD2YVSSyyBf/N2f7SFzmIMGzAyXQb238kFnXhVHAgMBAAGjQjBA\nMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMB0GA1UdDgQWBBSnDb38\nrn2R8PugVy4gKQmwA/CFbjANBgkqhkiG9w0BAQsFAAOCAYEApmuABIj10U4oLNh3\nHzEAAsoRsDG3g/3nxD+pTuqyhds1Y4QrO+AI5MYMeMgqHnGdC9mcU6tUC1O2UboD\n2HSFP8wRyofXtugXae13CSknX6pWyQ+00IzFiebL1Q7EEdxnJMA4jVT9wfukvNiQ\nJK+sBoHw5zvlZr1YUSH6RpGzOnTDkWhPwTifOJyfHfq6jC99MFY6EEnLKKtka37q\nft/CtBsex7GpfDnOTusc/0AyLw4YsA97JF7GZ6CFlYmrtKcqz0BvJ/YakHgXV1Qj\nLXylsFm/5KNBr1k3XymsUktxGSTFp7l4QM/KFIa2wqYjupUzRgYSpE5qugeana/t\n5a/sJiMQ+cz/QVhKFTVnS7BT8i1a8SELfBhimg9KbOKKx5zEfRp3an0KmvX9k7HU\nMmIfZ/1FjJTtxKNuOJAueWEMpteS/8uueBtYc+U/+0+P63D7izLwtx35Df8pWFc7\nLBy5u27PJIroi9Hgg0FG+ffSRUZeNOL/4TzXcybbkJWS9i8U\n-----END CERTIFICATE-----")
	rootCert, err := LoadCertificateFromPEM(rootCaPEM)
	assert.NoError(t, err, "Expected no error in parsing valid pem certificate")
	assert.NotNil(t, rootCert, "Expected root cert to not be nil")
}

func TestVerifyEKCertificateChain_virtualizedTPM(t *testing.T) {
	rootCaPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIEEDCCAnigAwIBAgIULlUfO3DQH6+jBto2jCHi2ZPV/ckwDQYJKoZIhvcNAQEL\nBQAwHzEdMBsGA1UEAxMUc3d0cG0tbG9jYWxjYS1yb290Y2EwIBcNMjUxMDIwMTQy\nMzExWhgPOTk5OTEyMzEyMzU5NTlaMB8xHTAbBgNVBAMTFHN3dHBtLWxvY2FsY2Et\ncm9vdGNhMIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEA4slS3pbbI+8E\nRwDKbHybjX6ghEsrIsek4NzLZZ4VknULK4LzY4+h1YA1ZGjJdyS3Ho+C718Tg5I9\nYuowRloj3ImPXfy1m66CVGHFU5xwe28SqTMKOWbMKXQLCd1K1+8uyunaAFgdfn81\nJSnX+n8ckIuEC90FRKAW4kEsmPINFZ2K/5s4gt+QxKnyBrbbusclOh4dE4R+y9Be\nph4SNX1OVahd19LFCmYM/At2D1ttVHloI3dCrSmKKsKJXItEVubAktsG2YlPFCk4\nKNtE0+NqbPHaR/SQDM12y+o6+6GebgYMV991hpOnKc0Tx0+VxVsmn+AUl4aMmM5P\nrcTooR1Sdh5J4ypMNkrvcztTK0sfBKV6eOuYCkHb7AYZwV0bSBQ87Ngyis34e2Ud\nYc9QV/CSMKK3NtzrPO/MDhNXBmZ+sRXxy+Z4/Zo+OixFPtE2NOJw0VN34TT7VZd7\nK0X83/7gF3T+yFD2YVSSyyBf/N2f7SFzmIMGzAyXQb238kFnXhVHAgMBAAGjQjBA\nMA8GA1UdEwEB/wQFMAMBAf8wDgYDVR0PAQH/BAQDAgIEMB0GA1UdDgQWBBSnDb38\nrn2R8PugVy4gKQmwA/CFbjANBgkqhkiG9w0BAQsFAAOCAYEApmuABIj10U4oLNh3\nHzEAAsoRsDG3g/3nxD+pTuqyhds1Y4QrO+AI5MYMeMgqHnGdC9mcU6tUC1O2UboD\n2HSFP8wRyofXtugXae13CSknX6pWyQ+00IzFiebL1Q7EEdxnJMA4jVT9wfukvNiQ\nJK+sBoHw5zvlZr1YUSH6RpGzOnTDkWhPwTifOJyfHfq6jC99MFY6EEnLKKtka37q\nft/CtBsex7GpfDnOTusc/0AyLw4YsA97JF7GZ6CFlYmrtKcqz0BvJ/YakHgXV1Qj\nLXylsFm/5KNBr1k3XymsUktxGSTFp7l4QM/KFIa2wqYjupUzRgYSpE5qugeana/t\n5a/sJiMQ+cz/QVhKFTVnS7BT8i1a8SELfBhimg9KbOKKx5zEfRp3an0KmvX9k7HU\nMmIfZ/1FjJTtxKNuOJAueWEMpteS/8uueBtYc+U/+0+P63D7izLwtx35Df8pWFc7\nLBy5u27PJIroi9Hgg0FG+ffSRUZeNOL/4TzXcybbkJWS9i8U\n-----END CERTIFICATE-----")
	ekCertPEM := []byte("-----BEGIN CERTIFICATE-----\nMIID9DCCAlygAwIBAgIBAjANBgkqhkiG9w0BAQsFADAYMRYwFAYDVQQDEw1zd3Rw\nbS1sb2NhbGNhMCAXDTI1MTAyMDE0MjMxMloYDzk5OTkxMjMxMjM1OTU5WjASMRAw\nDgYDVQQDEwd1bmtub3duMIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEA\nr6mFhtS39lhKRUymk5uqEydhswuJNyOqNv/8ckgF5RH5R5JcgwnXWAwc2Z6YIFhz\nD5Mgqpm2VImRWWLrDLhwZ3MWBcEqRWtiA5QmPTxaHeBwybXySlQiDnPgcR3/nWHq\njhQsioDlZj9YFqJVOd+vb14pF4Xlim+dUcCeD58cKovEKMJ0JT8442el0sguRWem\ntm3C3cfDzHJI0AOKnGeuIsCHdzruk5aT72b8HfcmGFaRL5kVdLt4sfloi1e7JBRB\n51RDOxs3hWv+ezp3ghf6c373j6P4/p8st9upbknYkO9E/P2YH66j/GNPoHUElKzk\nso2suwGasa0aeQGIHbMSpwIDAQABo4HMMIHJMBAGA1UdJQQJMAcGBWeBBQgBMFIG\nA1UdEQEB/wRIMEakRDBCMRYwFAYFZ4EFAgEMC2lkOjAwMDAxMDE0MRAwDgYFZ4EF\nAgIMBXN3dHBtMRYwFAYFZ4EFAgMMC2lkOjIwMTkxMDIzMAwGA1UdEwEB/wQCMAAw\nIgYDVR0JBBswGTAXBgVngQUCEDEOMAwMAzIuMAIBAAICAKQwHwYDVR0jBBgwFoAU\nBWhhkjdRrl248/KyiteN4nMR5XEwDgYDVR0PAQH/BAQDAgUgMA0GCSqGSIb3DQEB\nCwUAA4IBgQBX+wbDtWpPUkGpDxwOioyoo8PhpkfysTAac5vTmx0rr2aOFiuGF37w\ndM/6QoJ2n35WeRXhWSLri3WdWMvmHVIG7Sqvl/FqxF4MbAxJYY9OCozL8LBZsZ3U\nhMTRLOCHkPwbElYDU2CUSgBBMxPIJikNRGX6bleTE+HtdJBv9xGAnKqU92j4ehvV\nyEXJkPWgf2CgjMLfNtGapNw3rXnP69TaoJNOqYreyaNOBu1kSjRO1Vb2mqMjfjVB\nvZyiDBPQ/wviAi+W85lNbJ+khVXgyEAgPnbCopMfxZ2WbugMmuYH675OlEg/2NlX\nhNHb6DIyDxUjB0gOWOhLVd38NzPdcaXWljQLz9QMpriwRb37QLIfOYvzFlTnpEoQ\nqCTXjjcICy2KVzaqW+AR+KLBwVeaRhRYf+CQ0+DB7lk6O6B7U7Kj1NhE0qVCncLh\n5wnc1aPQBFEIhvRQa0nzqxKMDf7dGl9zYL6YZ1XnXtXQEQDPxlShZPQ8DI+EcNvy\n6sOwW2+BwJU=\n-----END CERTIFICATE-----")
	rootCert, err := LoadCertificateFromPEM(rootCaPEM)
	assert.NoError(t, err, "Expected no error in parsing valid pem certificate")
	assert.NotNil(t, rootCert, "Expected root cert to not be nil")

	ekCert, err := LoadCertificateFromPEM(ekCertPEM)
	assert.NoError(t, err, "Expected no error in parsing ek certificate")
	assert.NotNil(t, ekCert, "Expected ek cert to not be nil")

	tpmVendors := []TPMVendor{
		{
			Name:  "swTPM",
			TCGId: "id:00001014",
		},
	}

	err = VerifyEKCertificateChain(ekCert, nil, rootCert, tpmVendors)
	assert.NoError(t, err, "Expected no error in verifying EK certificate")

}

func TestVerifyEKCertificateChain_physicalTPM(t *testing.T) {
	rootCaPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIFszCCA5ugAwIBAgIEasM5FDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJE\nRTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJP\nUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkg\nUlNBIFJvb3QgQ0EwHhcNMTQxMTI0MTUzNzE2WhcNMzQxMTI0MTUzNzE2WjCBgzEL\nMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEa\nMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9Q\nVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDAzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAuUD5SLLVYRmuxDjT3cWQbRTywTWUVFE3EupJQZjJ\n9mvFc2KcjpQv6rpdaT4JC33P1M9iJgrHwYO0AZlGl2FcFpSNkc/3CWoMTT9rOdwS\n/MxlNSkxwTz6IAYUYh7+pd7T49NpRRGZ1dOMfyOxWgA4C0g3EP/ciIvA2cCZ95Hf\nARD9NhuG2DAEYGNRSHY2d/Oxu+7ytzkGFFj0h1jnvGNJpWNCf3CG8aNc5gJAduMr\nWcaMHb+6fWEysg++F2FLav813+/61FqvSrUMsQg0lpE16KBA5QC2Wcr/kLZGVVGc\nuALtgJ/bnd8XgEv7W8WG+jyblUe+hkZWmxYluHS3yJeRbwIDAQABo4IBODCCATQw\nVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzAChjtodHRwOi8vcGtpLmluZmluZW9u\nLmNvbS9PcHRpZ2FSc2FSb290Q0EvT3B0aWdhUnNhUm9vdENBLmNydDAdBgNVHQ4E\nFgQUQLhoK40YRQorBoSdm1zZb0zd9L4wDgYDVR0PAQH/BAQDAgAGMBIGA1UdEwEB\n/wQIMAYBAf8CAQAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL3BraS5pbmZpbmVv\nbi5jb20vT3B0aWdhUnNhUm9vdENBL09wdGlnYVJzYVJvb3RDQS5jcmwwFQYDVR0g\nBA4wDDAKBggqghQARAEUATAfBgNVHSMEGDAWgBTcu1ar8Rj8ppp1ERBlhBKe1UGS\nuTAQBgNVHSUECTAHBgVngQUIATANBgkqhkiG9w0BAQsFAAOCAgEAeUzrsGq3oQOT\nmF7g71TtMMndwPxgZvaB4bAc7dNettn5Yc1usikERfvJu4/iBs/Tdl6z6TokO+6V\nJuBb6PDV7f5MFfffeThraPCTeDcyYBzQRGnoCxc8Kf81ZJT04ef8CQkkfuZHW1pO\n+HHM1ZfFfNdNTay1h83x1lg1U0KnlmJ5KCVFiB94owr9t5cUoiSbAsPcpqCrWczo\nRsg1aTpokwI8Y45lqgt0SxEmQw2PIAEjHG2GQcLBDeI0c7cK5OMEjSMXStJHmNbp\nu4RHXzd+47nCD2kGV8Bx5QnK8qDVAFAe/UTDQi5mTtDFRL36Nns7jz8USemu+bw9\nl24PN73rKcB2wNF2/oFTLPHkdYfTKYGXG1g2ZkDcTAENSOq3fcTfAuyHQozBwYHG\nGGyyPHy6KvLkqMQuqeDv0QxGOtE+6cedFMP2D9bMaujR389mSm7DE6YyNQClRW7w\nJ1+rNYuN2vErvB96ir1zljXq0yMxrm5nTeiAT4p5eoFqoeSYDbFljt/f+PebREiO\nnJIy4fdvKlHAf70gPdYpYipc4oTZxLeWjDQxRFFBDFrnLdlPSg6zSL2Q3ANAEI3y\nMtHaEaU0wbaBvezyzMUHI5nLnYFL+QRP4N2OFNI/ejBaEpmIXzf6+/eF40MNLHuR\n9/B93Q+hpw8O6XZ7qx697I+5+smLlPQ=\n-----END CERTIFICATE-----")
	intermediateCaPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIFqzCCA5OgAwIBAgIBAzANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJERTEh\nMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJPUFRJ\nR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkgUlNB\nIFJvb3QgQ0EwHhcNMTMwNzI2MDAwMDAwWhcNNDMwNzI1MjM1OTU5WjB3MQswCQYD\nVQQGEwJERTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYD\nVQQLDBJPUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElH\nQShUTSkgUlNBIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC\nAQC7E+gc0B5T7awzux66zMMZMTtCkPqGv6a3NVx73ICg2DSwnipFwBiUl9soEodn\n25SVVN7pqmvKA2gMTR5QexuYS9PPerfRZrBY00xyFx84V+mIRPg4YqUMLtZBcAwr\nR3GO6cffHp20SBH5ITpuqKciwb0v5ueLdtZHYRPq1+jgy58IFY/vACyF/ccWZxUS\nJRNSe4ruwBgI7NMWicxiiWQmz1fE3e0mUGQ1tu4M6MpZPxTZxWzN0mMz9noj1oIT\nZUnq/drN54LHzX45l+2b14f5FkvtcXxJ7OCkI7lmWIt8s5fE4HhixEgsR2RX5hzl\n8XiHiS7uD3pQhBYSBN5IBbVWREex1IUat5eAOb9AXjnZ7ivxJKiY/BkOmrNgN8k2\n7vOS4P81ix1GnXsjyHJ6mOtWRC9UHfvJcvM3U9tuU+3dRfib03NGxSPnKteL4SP1\nbdHfiGjV3LIxzFHOfdjM2cvFJ6jXg5hwXCFSdsQm5e2BfT3dWDBSfR4h3Prpkl6d\ncAyb3nNtMK3HR5yl6QBuJybw8afHT3KRbwvOHOCR0ZVJTszclEPcM3NQdwFlhqLS\nghIflaKSPv9yHTKeg2AB5q9JSG2nwSTrjDKRab225+zJ0yylH5NwxIBLaVHDyAEu\n81af+wnm99oqgvJuDKSQGyLf6sCeuy81wQYO46yNa+xJwQIDAQABo0IwQDAdBgNV\nHQ4EFgQU3LtWq/EY/KaadREQZYQSntVBkrkwDgYDVR0PAQH/BAQDAgAGMA8GA1Ud\nEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAGHTBUx3ETIXYJsaAgb2pyyN\nUltVL2bKzGMVSsnTCrXUU8hKrDQh3jNIMrS0d6dU/fGaGJvehxmmJfjaN/IFWA4M\nBdZEnpAe2fJEP8vbLa/QHVfsAVuotLD6QWAqeaC2txpxkerveoV2JAwj1jrprT4y\nrkS8SxZuKS05rYdlG30GjOKTq81amQtGf2NlNiM0lBB/SKTt0Uv5TK0jIWbz2WoZ\ngGut7mF0md1rHRauWRcoHQdxWSQTCTtgoQzeBj4IS6N3QxQBKV9LL9UWm+CMIT7Y\nnp8bSJ8oW4UdpSuYWe1ZwSjZyzDiSzpuc4gTS6aHfMmEfoVwC8HN03/HD6B1Lwo2\nDvEaqAxkya9IYWrDqkMrEErJO6cqx/vfIcfY/8JYmUJGTmvVlaODJTwYwov/2rjr\nla5gR+xrTM7dq8bZimSQTO8h6cdL6u+3c8mGriCQkNZIZEac/Gdn+KwydaOZIcnf\nRdp3SalxsSp6cWwJGE4wpYKB2ClM2QF3yNQoTGNwMlpsxnU72ihDi/RxyaRTz9OR\npubNq8Wuq7jQUs5U00ryrMCZog1cxLzyfZwwCYh6O2CmbvMoydHNy5CU3ygxaLWv\nJpgZVHN103npVMR3mLNa3QE+5MFlBlP3Mmystu8iVAKJas39VO5y5jad4dRLkwtM\n6sJa8iBpdRjZrBp5sJBI\n-----END CERTIFICATE-----")
	ekCertPEM := []byte("-----BEGIN CERTIFICATE-----\nMIIElTCCA32gAwIBAgIEFMzNOTANBgkqhkiG9w0BAQsFADCBgzELMAkGA1UEBhMC\nREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEaMBgGA1UECwwR\nT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9QVElHQShUTSkg\nUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDAzMB4XDTE2MDEwMTEzMTAyMloXDTMxMDEw\nMTEzMTAyMlowADCCASIwDQYJKoZIhvcNAQEBBQADggEPADCCAQoCggEBAISFY3i9\nWciX46z/ALiAKejoHbxDOTyldeUPYwNVxU9rOEuWl9EvB+cn//ecWPeVXjj1rqYP\nwZztCDPORjHa93JnW+z75brKmtekC1O8R9ii8oAyEHmwvvgxHd8oOLqHBfTvodn2\n1pE6gxbeZCETU6FcpqVMHJJQBpNocX7nOX/2QqJW10MkUN+b8EodEv7xJ5dFV7B6\nkG9UowP1hqgSngG4gOrm3wAfXREsU0ne9KYTSZwXWb6JErIM0OqY/1Uv4fNmd5BQ\nUJwXQK4WKfQlT5++d2oJHpYkF99CHM4l/JlSg1+apZ80cGfNA9nhuk/E89lrc7MM\nITuVMCij4Mu9XqMCAwEAAaOCAZEwggGNMFsGCCsGAQUFBwEBBE8wTTBLBggrBgEF\nBQcwAoY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0EwMDMv\nT3B0aWdhUnNhTWZyQ0EwMDMuY3J0MA4GA1UdDwEB/wQEAwIAIDBRBgNVHREBAf8E\nRzBFpEMwQTEWMBQGBWeBBQIBDAtpZDo0OTQ2NTgwMDETMBEGBWeBBQICDAhTTEIg\nOTY2NTESMBAGBWeBBQIDDAdpZDowNTI4MAwGA1UdEwEB/wQCMAAwUAYDVR0fBEkw\nRzBFoEOgQYY/aHR0cDovL3BraS5pbmZpbmVvbi5jb20vT3B0aWdhUnNhTWZyQ0Ew\nMDMvT3B0aWdhUnNhTWZyQ0EwMDMuY3JsMBUGA1UdIAQOMAwwCgYIKoIUAEQBFAEw\nHwYDVR0jBBgwFoAUQLhoK40YRQorBoSdm1zZb0zd9L4wEAYDVR0lBAkwBwYFZ4EF\nCAEwIQYDVR0JBBowGDAWBgVngQUCEDENMAsMAzIuMAIBAAIBdDANBgkqhkiG9w0B\nAQsFAAOCAQEApynlEZGc4caT7bQJjhrvOtv4RFu3FNA9hgsF+2BGltsumqo9n3nU\nGoGt65A5mJAMCY1gGF1knvUFq8ey+UuIFw3QulHGENOiRu0aT3x9W7c6BxQIDFFC\nPtA+Qvvg+HJJ6XjihQRc3DU01HZm3xD//fGIDuYasZwBd2g/Ejedp2tKBl2M98FO\n48mbZ4WtaPrEALn3UQMf27pWqe2hUKFSKDEurijnchsdmRjTmUEWM1/9GFkh6IrT\nYvRBngNqOffJ+If+PI3x2GXkGnzsA6IxroEY9CwOhmNp+6xbAgqUedd5fWMLBN3Q\nMjHSp1Sl8wp00xRztfh0diBdicy3Hbn03g==\n-----END CERTIFICATE-----")

	rootCert, err := LoadCertificateFromPEM(rootCaPEM)
	assert.NoError(t, err, "Expected no error in parsing valid pem certificate")
	assert.NotNil(t, rootCert, "Expected root cert to not be nil")

	intermediateCaCert, err := LoadCertificateFromPEM(intermediateCaPEM)
	assert.NoError(t, err, "Expected no error in parsing ek certificate")
	assert.NotNil(t, intermediateCaCert, "Expected ek cert to not be nil")

	ekCert, err := LoadCertificateFromPEM(ekCertPEM)
	assert.NoError(t, err, "Expected no error in parsing ek certificate")
	assert.NotNil(t, ekCert, "Expected ek cert to not be nil")

	tpmVendors := []TPMVendor{
		{
			Name:  "Infineon",
			TCGId: "id:49465800",
		},
	}

	err = VerifyEKCertificateChain(ekCert, []*x509.Certificate{intermediateCaCert}, rootCert, tpmVendors)
	assert.NoError(t, err, "Expected no error in verifying EK certificate")

}
