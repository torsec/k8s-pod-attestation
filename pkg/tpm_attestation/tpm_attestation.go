package tpm_attestation

import (
	"bytes"
	"crypto"
	"crypto/subtle"
	"fmt"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/legacy/tpm2/credactivation"
	"github.com/google/go-tpm/tpmutil"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
)

const symBlockSize = 16

func ValidateAIKPublicData(aikNameData, aikPublicArea []byte, aikTemplate tpm2legacy.Public) (crypto.PublicKey, error) {
	retrievedName, err := tpm2legacy.DecodeName(bytes.NewBuffer(aikNameData))
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
	pubHash.Write(aikPublicArea)
	pubDigest := pubHash.Sum(nil)

	if !bytes.Equal(retrievedName.Digest.Value, pubDigest) {
		return nil, fmt.Errorf("computed AIK Name does not match received Name digest")
	}

	retrievedAKPublicArea, err := tpm2legacy.DecodePublic(aikPublicArea)
	if err != nil {
		return nil, fmt.Errorf("failed to decode received AIK Public Area")
	}

	if !retrievedAKPublicArea.MatchesTemplate(aikTemplate) {
		return nil, fmt.Errorf("provided AIK does not match AIK Template")
	}

	AIKPub, err := retrievedAKPublicArea.Key()
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AIK Public Key from AIK Public Area")
	}

	return AIKPub, nil
}

func GenerateCredentialActivation(AIKNameData []byte, ekPublic crypto.PublicKey, activateCredentialSecret []byte) ([]byte, []byte, error) {
	retrievedName, err := tpm2legacy.DecodeName(bytes.NewBuffer(AIKNameData))
	if err != nil {
		return nil, nil, fmt.Errorf("failed to decode AIK Name")
	}

	// Re-generate the credential blob and encrypted secret based on AK public info
	credentialBlob, encryptedSecret, err := credactivation.Generate(retrievedName.Digest, ekPublic, symBlockSize, activateCredentialSecret)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate credential activation challenge: %v", err)
	}

	return credentialBlob, encryptedSecret, nil
}

func ValidateQuoteStructure(quote *pb.Quote, nonce []byte) error {
	// Decode and check for magic TPMS_GENERATED_VALUE.
	attestationData, err := tpm2legacy.DecodeAttestationData(quote.GetQuote())
	if err != nil {
		return fmt.Errorf("decoding quote attestation data failed: %v", err)
	}

	if attestationData.Type != tpm2legacy.TagAttestQuote {
		return fmt.Errorf("expected quote tag, got: %v", attestationData.Type)
	}

	attestedQuoteInfo := attestationData.AttestedQuoteInfo
	if attestedQuoteInfo == nil {
		return fmt.Errorf("attestation data does not contain quote info")
	}

	if subtle.ConstantTimeCompare(attestationData.ExtraData, nonce) == 0 {
		return fmt.Errorf("quote extraData %v did not match expected extraData %v", attestationData.ExtraData, nonce)
	}

	pcrHashAlgo, err := ToCryptoHash(quote.GetPcrs().GetHash())
	if err != nil {
		return fmt.Errorf("failed to parse hash algorithm: %v", err)
	}

	err = validatePCRDigest(attestedQuoteInfo, quote.GetPcrs(), pcrHashAlgo)
	if err != nil {
		return fmt.Errorf("PCRs digest validation failed: %v", err)
	}

	return nil
}

func GetPCRValues(quote *pb.Quote) map[uint32][]byte {
	return quote.GetPcrs().GetPcrs()
}

func GetQuoteNonce(quote *pb.Quote) ([]byte, error) {
	attestationData, err := tpm2legacy.DecodeAttestationData(quote.GetQuote())
	if err != nil {
		return nil, fmt.Errorf("decoding quote attestation data failed: %v", err)
	}
	return attestationData.ExtraData, nil
}

func GetPCRValue(quote *pb.Quote, pcrIndex uint32) ([]byte, error) {
	pcrs := quote.GetPcrs().GetPcrs()
	pcrValue, exists := pcrs[pcrIndex]
	if !exists {
		return nil, fmt.Errorf("PCR index %d not found in quote PCRs", pcrIndex)
	}
	return pcrValue, nil
}

func GetPCRHashAlgorithm(quote *pb.Quote) (crypto.Hash, error) {
	return ToCryptoHash(quote.GetPcrs().GetHash())
}

func GetQuoteSignature(sig *tpm2legacy.Signature) ([]byte, crypto.Hash, error) {
	var rawSig []byte
	var err error
	var hashAlg crypto.Hash

	switch sig.Alg {
	case tpm2legacy.AlgRSASSA, tpm2legacy.AlgRSAPSS:
		rawSig, err = tpmutil.Pack(sig.RSA.Signature)
		if err != nil {
			return nil, crypto.Hash(0), fmt.Errorf("failed to pack RSA signature: %v", err)
		}
		hashAlg, err = sig.RSA.HashAlg.Hash()
		if err != nil {
			return nil, crypto.Hash(0), fmt.Errorf("failed to parse RSA signature hash algorithm: %v", err)
		}
		return rawSig, hashAlg, nil

	case tpm2legacy.AlgECDSA:
		ecdsaSig := cryptoUtils.ECDSASignature{R: sig.ECC.R, S: sig.ECC.S}
		rawSig, err = ecdsaSig.ToASN1()
		if err != nil {
			return nil, crypto.Hash(0), fmt.Errorf("failed to convert ECDSA signature to ASN.1 format: %v", err)
		}
		hashAlg, err = sig.ECC.HashAlg.Hash()
		if err != nil {
			return nil, crypto.Hash(0), fmt.Errorf("failed to parse ECDSA signature hash algorithm: %v", err)
		}
		return rawSig, hashAlg, nil

	default:
		return nil, crypto.Hash(0), fmt.Errorf("unsupported quote signature algorithm: %v", sig.Alg)
	}
}

func VerifyQuote(AIK crypto.PublicKey, quote *pb.Quote) error {
	sig, err := tpm2legacy.DecodeSignature(bytes.NewBuffer(quote.GetRawSig()))
	if err != nil {
		return fmt.Errorf("failed to decode quote Signature")
	}

	rawSig, sigAlgo, err := GetQuoteSignature(sig)
	if err != nil {
		return fmt.Errorf("failed to get quote signature: %v", err)
	}
	return cryptoUtils.VerifyMessage(AIK, quote.GetQuote(), rawSig, sigAlgo)
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

// ToCryptoHash maps a TPM supported hash algorithm (tpm.HashAlgo) to the corresponding crypto.Hash.
func ToCryptoHash(algo pb.HashAlgo) (crypto.Hash, error) {
	switch algo {
	case pb.HashAlgo_SHA1:
		return crypto.SHA1, nil
	case pb.HashAlgo_SHA256:
		return crypto.SHA256, nil
	case pb.HashAlgo_SHA384:
		return crypto.SHA384, nil
	case pb.HashAlgo_SHA512:
		return crypto.SHA512, nil
	default:
		return crypto.Hash(0), fmt.Errorf("unsupported hash algorithm: %v", algo)
	}
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
