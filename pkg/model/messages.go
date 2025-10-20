package model

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
	EKCert        string `json:"EKCert"`
	AIKNameData   string `json:"AIKNameData"`
	AIKPublicArea string `json:"AIKPublicArea"`
}

type WorkerChallenge struct {
	AIKCredential      string `json:"AIKCredential"`
	AIKEncryptedSecret string `json:"AIKEncryptedSecret"`
}

type WorkerChallengeResponse struct {
	Message         string `json:"message"`
	Status          string `json:"status"`
	HMAC            string `json:"HMAC"`
	WorkerBootQuote string `json:"workerBootQuote"`
}

type RegistrationAcknowledge struct {
	Message           string `json:"message"`
	Status            string `json:"status"`
	VerifierPublicKey string `json:"verifierPublicKey"`
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
	Signature string `json:"signature"`
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
	Manifest     string `json:"manifest"`
	Signature    string `json:"signature"`
}

type PodAttestationRequest struct {
	TenantName string `json:"tenantName"`
	PodName    string `json:"podName"`
	Signature  string `json:"signature"`
}

type AttestationRequest struct {
	Nonce       string `json:"nonce"`
	PodName     string `json:"podName"`
	PodUid      string `json:"podUid"`
	TenantId    string `json:"tenantId"`
	IMAMlOffset int64  `json:"imaMlOffset"`
	Signature   string `json:"signature,omitempty"`
}

type AttestationResponse struct {
	AttestationEvidence AttestationEvidence `json:"attestationEvidence,omitempty"`
	Message             string              `json:"message"`
	Status              string              `json:"status"`
}

type WorkerRegistrationConfirm struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type PodWhitelistCheckRequest struct {
	PodImageName   string     `json:"podImageName"`
	PodImageDigest string     `json:"podImageDigest"`
	PodFiles       []IMAEntry `json:"podFiles"`
	HashAlg        string     `json:"hashAlg"` // Include the hash algorithm in the request
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
