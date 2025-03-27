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
	PCRset PCRSet `json:"pcrs"`
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

type PodFileWhitelist struct {
	FilePath     string              `json:"filePath" bson:"filePath"`
	ValidDigests map[string][]string `json:"validDigests" bson:"validDigests"` // Hash algorithm as the key
}

type ImageWhitelist struct {
	ImageName   string             `json:"imageName" bson:"imageName"`
	ImageDigest string             `json:"imageDigest" bson:"imageDigest"`
	ValidFiles  []PodFileWhitelist `json:"validFiles" json:"validFiles"`
}

type IMAEntry struct {
	FilePath string `json:"filePath"`
	FileHash string `json:"fileHash"`
}

// OsWhitelist represents the structure of our stored document in MongoDB.
// It categorizes valid digests by hash algorithm.
type OsWhitelist struct {
	OSName       string              `json:"osName" bson:"osName"`
	ValidDigests map[string][]string `json:"validDigests" bson:"validDigests"` // Hash algorithm as the key
}

type ContainerDependencyWhitelist struct {
	FilePath     string              `json:"filePath" bson:"filePath"`
	ValidDigests map[string][]string `json:"validDigests" bson:"validDigests"` // Hash algorithm as the key
}

type ContainerRuntimeWhitelist struct {
	ContainerRuntimeName string                         `json:"containerRuntimeName" bson:"containerRuntimeName"`
	ValidFiles           []ContainerDependencyWhitelist `json:"validFiles" json:"validFiles"`
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
