package model

import (
	"crypto"
	"encoding/json"
	"fmt"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
)

const Success = "success"
const Error = "error"

type NewTenantRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type NewTPMCaCertRequest struct {
	TPMCaCertificate string `json:"tpmCaCertificate"`
}

type NewTPMVendorRequest struct {
	Name          string `json:"name"`
	TCGIdentifier string `json:"TCGIdentifier"`
}

type WorkerCredentialsResponse struct {
	UUID          string `json:"UUID"`
	EKCert        []byte `json:"EKCert"`
	AIKNameData   []byte `json:"AIKNameData"`
	AIKPublicArea []byte `json:"AIKPublicArea"`
}

type WorkerChallenge struct {
	AIKCredential      []byte `json:"AIKCredential"`
	AIKEncryptedSecret []byte `json:"AIKEncryptedSecret"`
}

type WorkerChallengeResponse struct {
	Message         string `json:"message"`
	Status          string `json:"status"`
	HMAC            []byte `json:"HMAC"`
	WorkerBootQuote []byte `json:"workerBootQuote"`
}

type RegistrationAcknowledge struct {
	Message           string `json:"message"`
	Status            string `json:"status"`
	VerifierPublicKey []byte `json:"verifierPublicKey"`
}

type WorkerWhitelistCheckRequest struct {
	OsName        string `json:"osName"`
	BootAggregate string `json:"bootAggregate"`
	HashAlg       string `json:"hashAlg"`
}

type VerifyTPMEKCertificateRequest struct {
	EKCertificate string `json:"EKCertificate"`
}

// VerifySignatureRequest represents the input data for signature verification
type VerifySignatureRequest struct {
	Name      string `json:"name"`
	Message   string `json:"message"`
	Signature []byte `json:"signature"`
}

type RegistrarResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type PodHandlerResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type DeploymentRequest struct {
	TenantName   string `json:"tenantName"`
	ResourceKind string `json:"resourceKind"`
	Manifest     []byte `json:"manifest"`
	Signature    []byte `json:"signature"`
}

type PodAttestationRequest struct {
	TenantName string `json:"tenantName"`
	PodName    string `json:"podName"`
	Signature  []byte `json:"signature"`
}

type AttestationRequest struct {
	Nonce       []byte `json:"nonce"`
	PodName     string `json:"podName"`
	PodUid      string `json:"podUid"`
	TenantId    string `json:"tenantId"`
	IMAMlOffset int64  `json:"imaMlOffset"`
	Signature   []byte `json:"signature,omitempty"`
}

func (ar *AttestationRequest) ToJSON() ([]byte, error) {
	arJSON, err := json.Marshal(ar)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Attestation Request: %v", err)
	}
	return arJSON, nil
}

func NewAttestationRequestFromJSON(data []byte) (*AttestationRequest, error) {
	var ar *AttestationRequest
	err := json.Unmarshal(data, ar)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal Attestation Request: %v", err)
	}
	return ar, nil
}

func (ar *AttestationRequest) VerifySignature(publicKey crypto.PublicKey, hashAlgo crypto.Hash) error {
	arCopy := *ar
	arCopy.Signature = nil
	arJSON, err := json.Marshal(arCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal Attestation Request for signature verification: %v", err)
	}
	err = cryptoUtils.VerifyMessage(publicKey, arJSON, ar.Signature, hashAlgo)
	if err != nil {
		return fmt.Errorf("attestation request signature verification failed: %v", err)
	}
	return nil
}

func (ar *AttestationRequest) Sign(key crypto.PrivateKey, hashAlgo crypto.Hash) error {
	arJSON, err := json.Marshal(ar)
	if err != nil {
		return fmt.Errorf("failed to marshal Attestation Request: %v", err)
	}
	ar.Signature, err = cryptoUtils.SignMessage(key, arJSON, hashAlgo)
	if err != nil {
		return fmt.Errorf("error while signing Attestation Request")
	}
	return nil
}

type AttestationResponse struct {
	Evidence Evidence `json:"evidence,omitempty"`
	Message  string   `json:"message"`
	Status   string   `json:"status"`
}

type WorkerRegistrationConfirm struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type PodWhitelistCheckRequest struct {
	ImageName   string     `json:"imageName"`
	ImageDigest string     `json:"imageDigest"`
	Files       []IMAEntry `json:"files"`
	HashAlg     string     `json:"hashAlg"` // Include the hash algorithm in the request
}

type AppendFilesToImageRequest struct {
	ImageName string           `json:"imageName"`
	NewFiles  PodFileWhitelist `json:"newFiles"`
}

type ContainerRuntimeCheckRequest struct {
	ContainerRuntimeName         string     `json:"containerRuntimeName"`
	ContainerRuntimeDependencies []IMAEntry `json:"containerRuntimeDependencies"`
	HashAlg                      string     `json:"hashAlg"` // Include the hash algorithm in the request
}

type WhitelistResponse struct {
	Message        string                  `json:"message"`
	Status         string                  `json:"status"`
	ErroredEntries ErroredWhitelistEntries `json:"erroredEntries,omitempty"`
}
