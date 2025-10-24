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
	"sync"
)

var bootReservedPCRs = []int{0, 1, 2, 3, 4, 5, 6, 7, 8, 9}

const SimulatorPath = "simulator"

type TPM struct {
	rwc       io.ReadWriteCloser
	tpmPath   string
	aikHandle tpmutil.Handle
	ekHandle  tpmutil.Handle
	mtx       sync.Mutex
}

func (tpm *TPM) Init(tpmPath string) {
	tpm.tpmPath = tpmPath
}

func (tpm *TPM) Open() {
	var err error
	if tpm.tpmPath == "" {
		logger.Fatal("Unable to open TPM: no device path provided")
	}

	if tpm.tpmPath == SimulatorPath {
		tpm.rwc, err = simulator.GetWithFixedSeedInsecure(1073741825)
		if err != nil {
			logger.Fatal("Unable to open TPM simulator: %v", err)
		}
	} else {
		tpm.rwc, err = tpmutil.OpenTPM(tpm.tpmPath)
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

func (tpm *TPM) GetWorkerEKCertificate() ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	EK, err := client.EndorsementKeyRSA(tpm.rwc)
	if err != nil {
		return nil, fmt.Errorf("unable to get RSA EK: %v", err)
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

// GetWorkerEKandCertificate is used to get TPM EK public key and certificate.
// It returns both the EK and the certificate to be compliant with simulator TPMs not provided with a certificate
func (tpm *TPM) GetWorkerEKandCertificate() ([]byte, []byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	EK, err := client.EndorsementKeyRSA(tpm.rwc)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to get RSA EK: %v", err)
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

	pemPublicEK := cryptoUtils.EncodePublicKeyToPEM(EK.PublicKey())
	return pemPublicEK, pemEKCert, nil
}

// CreateWorkerAIK creates a new AIK (Attestation Identity Key) for the Agent
func (tpm *TPM) CreateWorkerAIK() ([]byte, []byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	AIK, err := client.AttestationKeyRSA(tpm.rwc)
	if err != nil {
		return nil, nil, fmt.Errorf("unable to create RSA AIK: %v", err)
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

func GetPCRHashAlgo(algo crypto.Hash) (tpm2legacy.Algorithm, error) {
	tpmAlgo, err := tpm2legacy.HashToAlgorithm(algo)
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

func (tpm *TPM) QuoteGeneralPurposePCRs(nonce []byte, pcrsToQuote []int, bank crypto.Hash) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()
	// Custom function to return both found status and the PCR value
	pcrsContainsBootReserved, foundPCR := containsAndReturnPCR(pcrsToQuote)
	if pcrsContainsBootReserved {
		return nil, fmt.Errorf("cannot compute Quote on provided PCR set %v: boot reserved PCRs where included: %v", foundPCR, bootReservedPCRs)
	}

	pcrHashAlgo, err := GetPCRHashAlgo(bank)
	if err != nil {
		return nil, fmt.Errorf("cannot compute Quote on selected PCR bank: %v", err)
	}

	generalPurposePcrs := tpm2legacy.PCRSelection{
		Hash: pcrHashAlgo,
		PCRs: pcrsToQuote,
	}

	AIK, err := client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), tpm.aikHandle)
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

func (tpm *TPM) QuoteBootPCRs(nonce []byte, bank crypto.Hash) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	pcrHashAlgo, err := GetPCRHashAlgo(bank)
	if err != nil {
		return nil, fmt.Errorf("cannot compute Quote on selected PCR bank: %v", err)
	}

	bootPCRs := tpm2legacy.PCRSelection{
		Hash: pcrHashAlgo,
		PCRs: bootReservedPCRs,
	}

	AIK, err := client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), tpm.aikHandle)
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
	auth := tpm2legacy.AuthCommand{Session: tpm2legacy.HandlePasswordSession, Attributes: tpm2legacy.AttrContinueSession}
	if _, _, err = tpm2legacy.PolicySecret(tpm.rwc, tpm2legacy.HandleEndorsement, auth, session, nil, nil, nil, 0); err != nil {
		return nil, fmt.Errorf("policy secret failed: %v", err)
	}

	// Create authorization commands, linking session and password auth
	auths := []tpm2legacy.AuthCommand{
		{Session: tpm2legacy.HandlePasswordSession, Attributes: tpm2legacy.AttrContinueSession},
		{Session: session, Attributes: tpm2legacy.AttrContinueSession},
	}

	// Attempt to activate the credential
	challengeSecret, err := tpm2legacy.ActivateCredentialUsingAuth(tpm.rwc, auths, tpm.aikHandle, tpm.ekHandle, aikCredential[2:], aikEncryptedSecret[2:])
	if err != nil {
		return nil, fmt.Errorf("AIK activate_credential failed: %v", err)
	}
	return challengeSecret, nil
}

func (tpm *TPM) SignWithAIK(message []byte) ([]byte, error) {
	tpm.mtx.Lock()
	defer tpm.mtx.Unlock()

	if tpm.aikHandle.HandleValue() == 0 {
		return nil, fmt.Errorf("AIK is not already created")
	}

	AIK, err := client.NewCachedKey(tpm.rwc, tpm2legacy.HandleOwner, client.AKTemplateRSA(), tpm.aikHandle)
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
