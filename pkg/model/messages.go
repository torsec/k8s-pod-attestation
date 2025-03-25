package model

const Success = "success"
const Error = "error"

type NewTenantRequest struct {
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type WorkerResponse struct {
	UUID          string `json:"UUID"`
	EK            string `json:"EK"`
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
	EndorsementKey string `json:"endorsementKey"`
	EKCertificate  string `json:"EKCertificate"`
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

type PodDeploymentRequest struct {
	TenantName string `json:"tenantName"`
	Manifest   string `json:"manifest"`
	Signature  string `json:"signature"`
}

type PodAttestationRequest struct {
	TenantName string `json:"tenantName"`
	PodName    string `json:"podName"`
	Signature  string `json:"signature"`
}

type AttestationRequest struct {
	Nonce     string `json:"nonce"`
	PodName   string `json:"podName"`
	PodUid    string `json:"podUid"`
	TenantId  string `json:"tenantId"`
	Signature string `json:"signature,omitempty"`
}

type Evidence struct {
	PodName        string `json:"podName"`
	PodUID         string `json:"podUID"`
	TenantId       string `json:"tenantId"`
	Quote          string `json:"quote"`
	MeasurementLog string `json:"measurementLog"`
}

type AttestationResponse struct {
	Evidence  Evidence `json:"evidence"`
	Signature string   `json:"signature,omitempty"`
}
