package tpm_attestation

import (
	"bytes"
	"crypto"
	"crypto/rsa"
	"crypto/subtle"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"strconv"
)

const symBlockSize = 16

func ValidateAIKPublicData(aikNameData, aikPublicArea string) (*rsa.PublicKey, error) {
	decodedNameData, err := base64.StdEncoding.DecodeString(aikNameData)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AIK Name data")
	}

	decodedPublicArea, err := base64.StdEncoding.DecodeString(aikPublicArea)
	if err != nil {
		return nil, fmt.Errorf("failed to decode AIK Public Area data")
	}

	retrievedName, err := tpm2legacy.DecodeName(bytes.NewBuffer(decodedNameData))
	if err != nil {
		return nil, fmt.Errorf("failed to decode AIK Name")
	}

	if retrievedName.Digest == nil {
		return nil, fmt.Errorf("AIK Name is not a digest")
	}

	hash, err := retrievedName.Digest.Alg.Hash()
	if err != nil {
		return nil, fmt.Errorf("failed to get AIK Name hash: %v", err)
	}

	pubHash := hash.New()
	pubHash.Write(decodedPublicArea)
	pubDigest := pubHash.Sum(nil)

	if !bytes.Equal(retrievedName.Digest.Value, pubDigest) {
		return nil, fmt.Errorf("computed AIK Name does not match received Name digest")
	}

	retrievedAKPublicArea, err := tpm2legacy.DecodePublic(decodedPublicArea)
	if err != nil {
		return nil, fmt.Errorf("failed to decode received AIK Public Area")
	}

	if !retrievedAKPublicArea.MatchesTemplate(client.AKTemplateRSA()) {
		return nil, fmt.Errorf("provided AIK does not match AIK Template")
	}

	AIKPub, err := retrievedAKPublicArea.Key()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AIK Public Key from AIK Public Area")
	}

	return AIKPub.(*rsa.PublicKey), nil
}

func GenerateCredentialActivation(AIKNameData string, ekPublic *rsa.PublicKey, activateCredentialSecret []byte) (string, string, error) {
	decodedNameData, err := base64.StdEncoding.DecodeString(AIKNameData)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode AIK Name data")
	}

	retrievedName, err := tpm2legacy.DecodeName(bytes.NewBuffer(decodedNameData))
	if err != nil {
		return "", "", fmt.Errorf("failed to decode AIK Name")
	}

	// Re-generate the credential blob and encrypted secret based on AK public info
	credentialBlob, encryptedSecret, err := credactivation.Generate(retrievedName.Digest, ekPublic, symBlockSize, activateCredentialSecret)
	if err != nil {
		return "", "", fmt.Errorf("failed to generate credential activation challenge: %v", err)
	}

	encodedCredentialBlob := base64.StdEncoding.EncodeToString(credentialBlob)
	encodedEncryptedSecret := base64.StdEncoding.EncodeToString(encryptedSecret)

	return encodedCredentialBlob, encodedEncryptedSecret, nil
}

func ValidatePodQuote(podQuote *model.InputQuote, nonce []byte) (string, string, string, error) {
	// Decode Base64-encoded quote and signature
	quoteBytes, err := base64.StdEncoding.DecodeString(podQuote.Quote)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode Quote: %v", err)
	}

	// Decode Base64-encoded quote and signature
	quoteSig, err := base64.StdEncoding.DecodeString(podQuote.RawSig)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode Quote: %v", err)
	}

	sig, err := tpm2legacy.DecodeSignature(bytes.NewBuffer(quoteSig))
	if err != nil {
		return "", "", fmt.Errorf("failed to decode quote Signature")
	}

	// Decode and check for magic TPMS_GENERATED_VALUE.
	attestationData, err := tpm2legacy.DecodeAttestationData(quoteBytes)
	if err != nil {
		return "", "", fmt.Errorf("decoding quote attestation data failed: %v", err)
	}
	if attestationData.Type != tpm2legacy.TagAttestQuote {
		return "", "", fmt.Errorf("expected quote tag, got: %v", attestationData.Type)
	}
	attestedQuoteInfo := attestationData.AttestedQuoteInfo
	if attestedQuoteInfo == nil {
		return "", "", fmt.Errorf("attestation data does not contain quote info")
	}
	if subtle.ConstantTimeCompare(attestationData.ExtraData, nonce) == 0 {
		return "", "", fmt.Errorf("quote extraData %v did not match expected extraData %v", attestationData.ExtraData, nonce)
	}

	inputPCRs, err := convertPCRs(podQuote.PCRset.PCRs)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert PCRs from received quote")
	}

	quotePCRs := &pb.PCRs{
		Hash: pb.HashAlgo(podQuote.PCRset.Hash),
		Pcrs: inputPCRs,
	}

	pcrHashAlgo, err := convertToCryptoHash(quotePCRs.GetHash())
	if err != nil {
		return "", "", fmt.Errorf("failed to parse hash algorithm: %v", err)
	}

	err = validatePCRDigest(attestedQuoteInfo, quotePCRs, pcrHashAlgo)
	if err != nil {
		return "", "", fmt.Errorf("PCRs digest validation failed: %v", err)
	}

	return hex.EncodeToString(quotePCRs.GetPcrs()[10]), quotePCRs.GetHash().String(), nil
}
func ValidateWorkerQuote(workerQuote *model.InputQuote, nonce []byte, AIK *rsa.PublicKey) (string, string, error) {
	// Decode Base64-encoded quote and signature
	quoteBytes, err := base64.StdEncoding.DecodeString(workerQuote.Quote)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode Quote: %v", err)
	}

	// Decode Base64-encoded quote and signature
	quoteSig, err := base64.StdEncoding.DecodeString(workerQuote.RawSig)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode Quote: %v", err)
	}

	sig, err := tpm2legacy.DecodeSignature(bytes.NewBuffer(quoteSig))
	if err != nil {
		return "", "", fmt.Errorf("failed to decode quote Signature")
	}

	// Verify the signature
	if cryptoUtils.VerifySignature(AIK, quoteBytes, sig.RSA.Signature) != nil {
		return "", "", fmt.Errorf("quote signature verification failed")
	}

	// Decode and check for magic TPMS_GENERATED_VALUE.
	attestationData, err := tpm2legacy.DecodeAttestationData(quoteBytes)
	if err != nil {
		return "", "", fmt.Errorf("decoding quote attestation data failed: %v", err)
	}
	if attestationData.Type != tpm2legacy.TagAttestQuote {
		return "", "", fmt.Errorf("expected quote tag, got: %v", attestationData.Type)
	}
	attestedQuoteInfo := attestationData.AttestedQuoteInfo
	if attestedQuoteInfo == nil {
		return "", "", fmt.Errorf("attestation data does not contain quote info")
	}
	if subtle.ConstantTimeCompare(attestationData.ExtraData, nonce) == 0 {
		return "", "", fmt.Errorf("quote extraData %v did not match expected extraData %v", attestationData.ExtraData, nonce)
	}

	inputPCRs, err := convertPCRs(workerQuote.PCRset.PCRs)
	if err != nil {
		return "", "", fmt.Errorf("failed to convert PCRs from received quote")
	}

	quotePCRs := &pb.PCRs{
		Hash: pb.HashAlgo(workerQuote.PCRset.Hash),
		Pcrs: inputPCRs,
	}

	pcrHashAlgo, err := convertToCryptoHash(quotePCRs.GetHash())
	if err != nil {
		return "", "", fmt.Errorf("failed to parse hash algorithm: %v", err)
	}

	err = validatePCRDigest(attestedQuoteInfo, quotePCRs, pcrHashAlgo)
	if err != nil {
		return "", "", fmt.Errorf("PCRs digest validation failed: %v", err)
	}

	return hex.EncodeToString(attestedQuoteInfo.PCRDigest), quotePCRs.GetHash().String(), nil
}

func convertToCryptoHash(algo pb.HashAlgo) (crypto.Hash, error) {
	switch algo {
	case 4:
		return crypto.SHA1, nil
	case 11:
		return crypto.SHA256, nil
	case 12:
		return crypto.SHA384, nil
	case 13:
		return crypto.SHA512, nil
	default:
		return 0, fmt.Errorf("unsupported hash algorithm: %v", algo)
	}
}

func convertPCRs(input map[string]string) (map[uint32][]byte, error) {
	converted := make(map[uint32][]byte)

	// Iterate over the input map
	for key, value := range input {
		// Convert string key to uint32
		keyUint32, err := strconv.ParseUint(key, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("failed to convert key '%s' to uint32: %v", key, err)
		}

		// Decode base64-encoded value
		valueBytes, err := base64.StdEncoding.DecodeString(value)
		if err != nil {
			return nil, fmt.Errorf("failed to decode base64 value for key '%s': %v", key, err)
		}

		// Add the converted key-value pair to the new map
		converted[uint32(keyUint32)] = valueBytes
	}

	return converted, nil
}

func validatePCRDigest(quoteInfo *tpm2legacy.QuoteInfo, pcrs *pb.PCRs, hash crypto.Hash) error {
	if !samePCRSelection(pcrs, quoteInfo.PCRSelection) {
		return fmt.Errorf("given PCRs and Quote do not have the same PCR selection")
	}
	pcrDigest := pcrDigest(pcrs, hash)
	if subtle.ConstantTimeCompare(quoteInfo.PCRDigest, pcrDigest) == 0 {
		return fmt.Errorf("given PCRs digest not matching")
	}
	return nil
}

// PCRDigest computes the digest of the Pcrs. Note that the digest hash
// algorithm may differ from the PCRs' hash (which denotes the PCR bank).
func pcrDigest(p *pb.PCRs, hashAlg crypto.Hash) []byte {
	hash := hashAlg.New()
	for i := uint32(0); i < 24; i++ {
		if pcrValue, exists := p.GetPcrs()[i]; exists {
			hash.Write(pcrValue)
		}
	}
	return hash.Sum(nil)
}

// SamePCRSelection checks if the Pcrs has the same PCRSelection as the
// provided given tpm2.PCRSelection (including the hash algorithm).
func samePCRSelection(p *pb.PCRs, sel tpm2legacy.PCRSelection) bool {
	if tpm2legacy.Algorithm(p.GetHash()) != sel.Hash {
		return false
	}
	if len(p.GetPcrs()) != len(sel.PCRs) {
		return false
	}
	for _, pcr := range sel.PCRs {
		if _, ok := p.Pcrs[uint32(pcr)]; !ok {
			return false
		}
	}
	return true
}
