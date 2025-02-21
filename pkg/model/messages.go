package model

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
