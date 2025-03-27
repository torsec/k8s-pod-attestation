package model

// Struct definitions
type Tenant struct {
	TenantId  string `json:"tenantId"`
	Name      string `json:"name"`
	PublicKey string `json:"publicKey"`
}

type WorkerNode struct {
	WorkerId string `json:"workerId"`
	Name     string `json:"name"`
	AIK      string `json:"AIK"`
}

type InputQuote struct {
	Quote  string `json:"quote"`
	RawSig string `json:"raw_sig"`
	PCRs   PCRSet `json:"pcrs"`
}

// PCRSet represents the PCR values and the hash algorithm used
type PCRSet struct {
	Hash int               `json:"hash"`
	PCRs map[string]string `json:"pcrs"`
}

type TPMCACertificate struct {
	CertificateID  string `json:"certificateId,omitempty"`
	CommonName     string `json:"commonName"`
	PEMCertificate string `json:"PEMCertificate"`
}

type TPMVendor struct {
	VendorID      string `json:"vendorId,omitempty"`
	Name          string `json:"vendorName"`
	TCGIdentifier string `json:"TCGIdentifier"`
}

type AgentConfig struct {
	TPMPath                 string `json:"TPMPath"`
	IMAMountPath            string `json:"IMAMountPath"`
	IMAMeasurementLogPath   string `json:"IMAMeasurementLogPath"`
	ImageName               string `json:"imageName"`
	AgentPort               int32  `json:"agentPort"`
	AgentNodePortAllocation int32  `json:"agentNodePortAllocation"`
}

type Evidence struct {
	PodName        string `json:"podName"`
	Poduid         string `json:"podUID"`
	TenantId       string `json:"tenantId"`
	Quote          string `json:"quote"`
	MeasurementLog string `json:"measurementLog"`
}

/*
type PodStatus struct {
	PodName   string `json:"podName"`
	TenantId  string `json:"tenantId"`
	Status    string `json:"status"`
	Reason    string `json:"reason"`
	LastCheck string `json:"lastCheck"`
}
*/
