package tpm

import (
	"encoding/pem"
	"fmt"
	"github.com/google/go-tpm-tools/client"
	"github.com/google/go-tpm-tools/simulator"
	"github.com/google/go-tpm/tpmutil"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"io"
	"sync"
)

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
func (tpm *TPM) getWorkerEKandCertificate() (string, string, error) {
	tpm.tpmMtx.Lock()
	defer tpm.tpmMtx.Unlock()

	EK, err := client.EndorsementKeyRSA(tpm.rwc)
	if err != nil {
		return "", nil, fmt.Errorf("unable to get RSA EK: %v", err)
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
	return pemPublicEK, string(pemEKCert), nil
}
