package model

import (
	"crypto"
	"encoding/json"
	"fmt"
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
	OsName        string      `json:"osName"`
	BootAggregate string      `json:"bootAggregate"`
	HashAlg       crypto.Hash `json:"hashAlg"`
}

type VerifyTPMEKCertificateRequest struct {
	EKCertificate string `json:"EKCertificate"`
}

// VerifySignatureRequest represents the input data for signature verification
type VerifySignatureRequest struct {
	Name      string     `json:"name"`
	Message   string     `json:"message"`
	Signature *Signature `json:"signature,omitempty"`
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
	TenantName   string     `json:"tenantName"`
	ResourceKind string     `json:"resourceKind"`
	Manifest     []byte     `json:"manifest"`
	Signature    *Signature `json:"signature,omitempty"`
}

type PodAttestationRequest struct {
	TenantName string     `json:"tenantName"`
	PodName    string     `json:"podName"`
	Signature  *Signature `json:"signature,omitempty"`
}

type AttestationRequest struct {
	Nonce       []byte     `json:"nonce"`
	IMAMlOffset int64      `json:"imaMlOffset"`
	Signature   *Signature `json:"signature,omitempty"`
}

func (ar *AttestationRequest) ToJSON() ([]byte, error) {
	arJSON, err := json.Marshal(ar)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Attestation Request: %v", err)
	}
	return arJSON, nil
}

func NewAttestationRequestFromJSON(data []byte) (*AttestationRequest, error) {
	var ar AttestationRequest
	err := json.Unmarshal(data, &ar)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal Attestation Request: %v", err)
	}
	return &ar, nil
}

func (ar *AttestationRequest) VerifySignature(publicKey crypto.PublicKey) error {
	arCopy := *ar
	arCopy.Signature = nil
	arJSON, err := json.Marshal(arCopy)
	if err != nil {
		return fmt.Errorf("failed to marshal Attestation Request for signature verification: %v", err)
	}
	err = ar.Signature.Verify(publicKey, arJSON)
	if err != nil {
		return fmt.Errorf("failed to verify Attestation Request signature: %v", err)
	}
	return nil
}

func (ar *AttestationRequest) Sign(key crypto.PrivateKey, hashAlgo crypto.Hash) error {
	ar.Signature = nil
	arJSON, err := json.Marshal(ar)
	if err != nil {
		return fmt.Errorf("failed to marshal Attestation Request: %v", err)
	}
	ar.Signature = &Signature{HashAlg: hashAlgo}
	err = ar.Signature.Sign(key, arJSON)
	if err != nil {
		return fmt.Errorf("failed to sign Attestation Request: %v", err)
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
	ImageName   string      `json:"imageName"`
	ImageDigest string      `json:"imageDigest"`
	Files       []IMAEntry  `json:"files"`
	HashAlg     crypto.Hash `json:"hashAlg"` // Include the hash algorithm in the request
}

type AppendFilesToImageRequest struct {
	ImageName string           `json:"imageName"`
	NewFiles  PodFileWhitelist `json:"newFiles"`
}

type ContainerRuntimeCheckRequest struct {
	Name         string      `json:"name"`
	Dependencies []IMAEntry  `json:"dependencies"`
	HashAlg      crypto.Hash `json:"hashAlg"` // Include the hash algorithm in the request
}

type WhitelistResponse struct {
	Message        string         `json:"message"`
	Status         string         `json:"status"`
	ErroredEntries ErroredEntries `json:"erroredEntries,omitempty"`
}
