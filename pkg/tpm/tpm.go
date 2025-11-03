package tpm

import (
	"crypto"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	tpm2legacy "github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"io"
	"slices"
	"strings"
	"sync"
)

var bootReservedPCRs = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

const SimulatorPath = "simulator"

type KeyType int

const (
	RSA KeyType = 1 + iota
	ECC
)

func KeyTypeFromString(s string) (KeyType, error) {
	switch strings.ToUpper(s) {
	case "RSA":
		return RSA, nil
	case "ECC":
		return ECC, nil
	default:
		return 0, fmt.Errorf("unsupported key type: %s", s)
	}
}

func (k KeyType) String() string {
	switch k {
	case RSA:
		return "RSA"
	case ECC:
		return "ECC"
	default:
		return "Unknown"
	}
}

type TPM struct {
	rwc       io.ReadWriteCloser
	Path      string
	aikHandle tpmutil.Handle
	ekHandle  tpmutil.Handle
	mtx       sync.Mutex
}

func (tpm *TPM) Init(tpmPath string) {
	tpm.Path = tpmPath
}

func (tpm *TPM) Open() {
	var err error
	if tpm.Path == "" {
		logger.Fatal("Unable to open TPM: no device path provided")
	}

	if tpm.Path == SimulatorPath {
		tpm.rwc, err = simulator.GetWithFixedSeedInsecure(1073741825)
		if err != nil {
			logger.Fatal("Unable to open TPM simulator: %v", err)
		}
	} else {
		tpm.rwc, err = tpmutil.OpenTPM(tpm.Path)
		if err != nil {
			logger.Fatal("unable to open TPM: %v", err)
		}
	}
}

func (tpm *TPM) Close() {
	err := tpm.rwc.Close()
	if err != nil {
		logger.Fatal("Unable to close TPM: %v", err)
	}
}

func (tpm *TPM) GetWorkerEKCertificate(keyType KeyType) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()
	var EK *client.Key
	var err error

	switch keyType {
	case RSA:
		EK, err = client.EndorsementKeyRSA(tpm.rwc)
		if err != nil {
			return nil, fmt.Errorf("unable to get RSA EK: %v", err)
		}
		break
	case ECC:
		EK, err = client.EndorsementKeyECC(tpm.rwc)
		if err != nil {
			return nil, fmt.Errorf("unable to get ECC EK: %v", err)
		}
		break
	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	tpm.ekHandle = EK.Handle()

	defer EK.Close()
	var pemEKCert []byte

	EKCert := EK.Cert()
	if EKCert != nil {
		pemEKCert = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: EKCert.Raw,
		})
		return pemEKCert, nil
	}
	return nil, fmt.Errorf("unable to get EK certificate")
}

func (tpm *TPM) ReadPCR(pcrIndex int, bankHash crypto.Hash) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	pcrHashAlgo, err := GetPCRHashAlgo(bankHash)
	if err != nil {
		return nil, fmt.Errorf("cannot read selected PCR bank: %v", err)
	}

	pcrSelection := tpm2legacy.PCRSelection{
		Hash: pcrHashAlgo,
		PCRs: []int{pcrIndex},
	}

	pcrValues, err := tpm2legacy.ReadPCRs(tpm.rwc, pcrSelection)
	if err != nil {
		return nil, fmt.Errorf("failed to read PCR %d: %v", pcrIndex, err)
	}
	return pcrValues[pcrIndex], nil
}

// GetWorkerEKandCertificate is used to get TPM EK public key and certificate.
// It returns both the EK and the certificate to be compliant with simulator TPMs not provided with a certificate
func (tpm *TPM) GetWorkerEKandCertificate(keyType KeyType) ([]byte, []byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	var EK *client.Key
	var err error

	switch keyType {
	case RSA:
		EK, err = client.EndorsementKeyRSA(tpm.rwc)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get RSA EK: %v", err)
		}
		break
	case ECC:
		EK, err = client.EndorsementKeyECC(tpm.rwc)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get ECC EK: %v", err)
		}
		break
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	tpm.ekHandle = EK.Handle()

	defer EK.Close()
	var pemEKCert []byte

	EKCert := EK.Cert()
	if EKCert != nil {
		pemEKCert = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: EKCert.Raw,
		})
	}

	if pemEKCert == nil {
		pemEKCert = []byte("EK Certificate not provided")
	}

	pemPublicEK, err := cryptoUtils.EncodePublicKeyToPEM(EK.PublicKey())
	if err != nil {
		return nil, nil, fmt.Errorf("unable to encode public key: %v", err)
	}
	return pemPublicEK, pemEKCert, nil
}

// CreateAIK creates a new AIK (Attestation Identity Key) for the Agent
func (tpm *TPM) CreateAIK(keyType KeyType) ([]byte, []byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	var AIK *client.Key
	var err error

	switch keyType {
	case RSA:
		AIK, err = client.EndorsementKeyRSA(tpm.rwc)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get RSA EK: %v", err)
		}
		break
	case ECC:
		AIK, err = client.EndorsementKeyECC(tpm.rwc)
		if err != nil {
			return nil, nil, fmt.Errorf("unable to get ECC EK: %v", err)
		}
		break
	default:
		return nil, nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	defer AIK.Close()

	// used to later retrieve newly created AIK inside the TPM
	tpm.aikHandle = AIK.Handle()

	AIKNameData, err := AIK.Name().Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode AIK Name data")
	}

	AIKPublicArea, err := AIK.PublicArea().Encode()
	if err != nil {
		return nil, nil, fmt.Errorf("failed to encode AIK public area")
	}
	// Return AIK material
	return AIKNameData, AIKPublicArea, nil
}

// Custom function that checks if PCRstoQuote contains any element from bootReservedPCRs
// and returns the boolean and the list of matching PCRs
func containsAndReturnPCR(pcrsToQuote []int) (bool, []int) {
	var foundPCRs []int
	for _, pcr := range pcrsToQuote {
		if slices.Contains(bootReservedPCRs, pcr) {
			foundPCRs = append(foundPCRs, pcr)
		}
	}
	if len(foundPCRs) == 0 {
		return false, nil // No matching PCRs found
	}
	return true, foundPCRs
}

func GetPCRHashAlgo(alg crypto.Hash) (tpm2legacy.Algorithm, error) {
	tpmAlgo, err := tpm2legacy.HashToAlgorithm(alg)
	if err != nil {
		return tpm2legacy.AlgUnknown, fmt.Errorf("unable to determine hash algorithm: %v", err)
	}

	switch tpmAlgo {
	case tpm2legacy.AlgSHA1, tpm2legacy.AlgSHA256, tpm2legacy.AlgSHA384, tpm2legacy.AlgSHA512:
		return tpmAlgo, nil
	default:
		return tpm2legacy.AlgUnknown, fmt.Errorf("hash algorithm not supported for PCR bank: %v", tpmAlgo)
	}
}

func (tpm *TPM) QuoteGeneralPurposePCRs(nonce []byte, pcrsToQuote []int, bankHash crypto.Hash, keyType KeyType) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()
	// Custom function to return both found status and the PCR value
	pcrsContainsBootReserved, foundPCR := containsAndReturnPCR(pcrsToQuote)
	if pcrsContainsBootReserved {
		return nil, fmt.Errorf("cannot compute Quote on provided PCR set %v: boot reserved PCRs where included: %v", foundPCR, bootReservedPCRs)
	}

	pcrHashAlgo, err := GetPCRHashAlgo(bankHash)
	if err != nil {
		return nil, fmt.Errorf("cannot compute Quote on selected PCR bank: %v", err)
	}

	generalPurposePcrs := tpm2legacy.PCRSelection{
		Hash: pcrHashAlgo,
		PCRs: pcrsToQuote,
	}

	var template tpm2legacy.Public
	switch keyType {
	case RSA:
		template = client.AKTemplateRSA()
		break
	case ECC:
		template = client.AKTemplateECC()
		break
	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	AIK, err := client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, template, tpm.aikHandle)
	if err != nil {
		return nil, fmt.Errorf("error while retrieving AIK: %v", err)
	}

	quote, err := AIK.Quote(generalPurposePcrs, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create quote over PCRs %v: %v", pcrsToQuote, err)
	}
	quoteJSON, err := json.Marshal(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to parse quote result as json: %v", err)
	}
	return quoteJSON, nil
}

func (tpm *TPM) QuoteBootPCRs(nonce []byte, bankHash crypto.Hash, keyType KeyType) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	pcrHashAlgo, err := GetPCRHashAlgo(bankHash)
	if err != nil {
		return nil, fmt.Errorf("cannot compute Quote on selected PCR bankHash: %v", err)
	}

	bootPCRs := tpm2legacy.PCRSelection{
		Hash: pcrHashAlgo,
		PCRs: bootReservedPCRs,
	}

	var template tpm2legacy.Public
	switch keyType {
	case RSA:
		template = client.AKTemplateRSA()
		break
	case ECC:
		template = client.AKTemplateECC()
		break
	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	AIK, err := client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, template, tpm.aikHandle)
	if err != nil {
		return nil, fmt.Errorf("error while retrieving AIK: %v", err)
	}

	quote, err := AIK.Quote(bootPCRs, nonce)
	if err != nil {
		return nil, fmt.Errorf("failed to create quote over PCRs 0-9: %v", err)
	}
	quoteJSON, err := json.Marshal(quote)
	if err != nil {
		return nil, fmt.Errorf("failed to parse quote result as json: %v", err)
	}
	return quoteJSON, nil
}

func (tpm *TPM) ActivateAIKCredential(aikCredential, aikEncryptedSecret []byte) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()
	session, _, err := tpm2legacy.StartAuthSession(
		tpm.rwc,
		tpm2legacy.HandleNull,
		tpm2legacy.HandleNull,
		make([]byte, 16),
		nil,
		tpm2legacy.SessionPolicy,
		tpm2legacy.AlgNull,
		tpm2legacy.AlgSHA256,
	)
	if err != nil {
		return nil, fmt.Errorf("creating auth session failed: %v", err)
	}
	// Set PolicySecret on the endorsement handle, enabling EK use
	auth := tpm2legacy.AuthCommand{
		Session:    tpm2legacy.HandlePasswordSession,
		Attributes: tpm2legacy.AttrContinueSession,
	}
	if _, _, err = tpm2legacy.PolicySecret(tpm.rwc, tpm2legacy.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		return nil, fmt.Errorf("policy secret failed: %v", err)
	}

	// Create authorization commands, linking session and password auth
	auths := []tpm2legacy.AuthCommand{
		{
			Session:    tpm2legacy.HandlePasswordSession,
			Attributes: tpm2legacy.AttrContinueSession,
		},
		{
			Session:    session,
			Attributes: tpm2legacy.AttrContinueSession,
		},
	}

	// Attempt to activate the credential
	challengeSecret, err := tpm2legacy.ActivateCredentialUsingAuth(tpm.rwc, auths, tpm.aikHandle, tpm.ekHandle, aikCredential[2:], aikEncryptedSecret[2:])
	if err != nil {
		return nil, fmt.Errorf("AIK activate_credential failed: %v", err)
	}
	return challengeSecret, nil
}

func (tpm *TPM) SignWithAIK(message []byte, keyType KeyType) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	if tpm.aikHandle.HandleValue() == 0 {
		return nil, fmt.Errorf("AIK is not already created")
	}

	var template tpm2legacy.Public
	switch keyType {
	case RSA:
		template = client.AKTemplateRSA()
		break
	case ECC:
		template = client.AKTemplateECC()
		break
	default:
		return nil, fmt.Errorf("unsupported key type: %v", keyType)
	}

	AIK, err := client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, template, tpm.aikHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve AIK from TPM")
	}

	defer AIK.Close()

	aikSigned, err := AIK.SignData(message)
	if err != nil {
		return nil, fmt.Errorf("failed to sign with AIK: %v", err)
	}
	return aikSigned, nil
}
