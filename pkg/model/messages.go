package model

import (
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/ima"
)

const Success = "success"
const Error = "error"

type NewTenantRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type NewTPMCaCertRequest struct {
	TPMCaCert string `json:"tpmCaCert"`
}

type NewTPMVendorRequest struct {
	Name  string `json:"name"`
	TCGId string `json:"TCGId"`
}

type WorkerCredentialsResponse struct {
	SimpleResponse `json:",inline"`
	UUID           string `json:"UUID"`
	EKCert         []byte `json:"EKCert"`
	AIKName        []byte `json:"AIKName"`
	AIKPublicArea  []byte `json:"AIKPublicArea"`
}

type WorkerChallenge struct {
	AIKCredential      []byte `json:"AIKCredential"`
	AIKEncryptedSecret []byte `json:"AIKEncryptedSecret"`
}

type WorkerChallengeResponse struct {
	SimpleResponse `json:",inline"`
	Evidence       *RatsEvidence `json:"evidence,omitempty"`
	HashAlgo       crypto.Hash   `json:"hashAlgo"`
}

type RegistrationAcknowledge struct {
	SimpleResponse    `json:",inline"`
	VerifierPublicKey []byte `json:"verifierPublicKey"`
}

type WorkerWhitelistCheckRequest struct {
	OsName        string      `json:"osName"`
	BootAggregate string      `json:"bootAggregate"`
	HashAlg       crypto.Hash `json:"hashAlg"`
}

type VerifyTPMEKCertificateRequest struct {
	EKCertificate []byte `json:"EKCertificate"`
}

// VerifySignatureRequest represents the input data for signature verification
type VerifySignatureRequest struct {
	Name      string     `json:"name"`
	Message   []byte     `json:"message"`
	Signature *Signature `json:"signature,omitempty"`
}

type RegistrarResponse struct {
	SimpleResponse `json:",inline"`
}

type PodHandlerResponse struct {
	SimpleResponse `json:",inline"`
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
	Nonce     []byte     `json:"nonce"`
	Offset    int64      `json:"offset"`
	Signature *Signature `json:"signature,omitempty"`
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
	SimpleResponse   `json:",inline"`
	Evidence         *RatsEvidence `json:"evidence,omitempty"`
	ImaPcr           uint32        `json:"imaPcr"`
	TemplateHashAlgo crypto.Hash   `json:"templateHashAlgo"`
	FileHashAlgo     crypto.Hash   `json:"fileHashAlgo"`
}

type WorkerRegistrationConfirm struct {
	SimpleResponse `json:",inline"`
}

type PodWhitelistCheckRequest struct {
	ImageName   string            `json:"imageName"`
	ImageDigest string            `json:"imageDigest"`
	Files       []ima.Measurement `json:"files"`
	HashAlg     crypto.Hash       `json:"hashAlg"` // Include the hash algorithm in the request
}

type AppendFilesToImageRequest struct {
	ImageName string        `json:"imageName"`
	Files     FileWhitelist `json:"files"`
}

type ContainerRuntimeCheckRequest struct {
	Name         string            `json:"name"`
	Dependencies []ima.Measurement `json:"dependencies"`
	HashAlg      crypto.Hash       `json:"hashAlg"` // Include the hash algorithm in the request
}

type WhitelistResponse struct {
	SimpleResponse `json:",inline"`
	ErroredEntries ErroredEntries `json:"erroredEntries,omitempty"`
}

type SimpleResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}
