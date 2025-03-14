package tpm

import (
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

type TPM struct {
	rwc       io.ReadWriteCloser
	tpmPath   string
	aikHandle tpmutil.Handle
	ekHandle  tpmutil.Handle
	tpmMtx    sync.Mutex
}

func (tpm *TPM) Init(tpmPath string) {
	tpm.tpmPath = tpmPath
}

func (tpm *TPM) openTPM() {
	var err error
	if tpm.tpmPath == "" {
		logger.Fatal("Unable to open TPM: no device path provided")
	}

	if tpm.tpmPath == "simulator" {
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

func (tpm *TPM) closeTPM() {
	err := tpm.rwc.Close()
	if err != nil {
		logger.Fatal("Unable to close TPM: %v", err)
	}
}

func (tpm *TPM) getWorkerEKCertificate() ([]byte, error) {
	tpm.tpmMtx.Lock()
	defer tpm.tpmMtx.Unlock()

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

// getWorkerEKandCertificate is used to get TPM EK public key and certificate.
// It returns both the EK and the certificate to be compliant with simulator TPMs not provided with a certificate
func (tpm *TPM) getWorkerEKandCertificate() ([]byte, []byte, error) {
	tpm.tpmMtx.Lock()
	defer tpm.tpmMtx.Unlock()

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

// Function to create a new AIK (Attestation Identity Key) for the Agent
func (tpm *TPM) createWorkerAIK() ([]byte, []byte, error) {
	tpm.tpmMtx.Lock()
	defer tpm.tpmMtx.Unlock()

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

func (tpm *TPM) quoteGeneralPurposePCRs(nonce []byte, pcrsToQuote []int) ([]byte, error) {
	tpm.tpmMtx.Lock()
	defer tpm.tpmMtx.Unlock()
	// Custom function to return both found status and the PCR value
	pcrsContainsBootReserved, foundPCR := containsAndReturnPCR(pcrsToQuote)
	if pcrsContainsBootReserved {
		return nil, fmt.Errorf("cannot compute Quote on provided PCR set %v: boot reserved PCRs where included: %v", foundPCR, bootReservedPCRs)
	}

	generalPurposePcrs := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
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

func (tpm *TPM) quoteBootAggregate(nonce []byte) ([]byte, error) {
	tpm.tpmMtx.Lock()
	defer tpm.tpmMtx.Unlock()

	bootPCRs := tpm2legacy.PCRSelection{
		Hash: tpm2legacy.AlgSHA256,
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

func (tpm *TPM) activateAIKCredential(aikCredential, aikEncryptedSecret []byte) ([]byte, error) {
	tpm.tpmMtx.Lock()
	defer tpm.tpmMtx.Unlock()
	/*
		decodedCredential, err := base64.StdEncoding.DecodeString(AIKCredential)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode AIK Credential")
		}
		decodedSecret, err := base64.StdEncoding.DecodeString(AIKEncryptedSecret)
		if err != nil {
			return nil, fmt.Errorf("Failed to decode AIK encrypted Secret")
		}
	*/

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
