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
	PodUid         string `json:"podUid"`
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

type AttestationResult struct {
	Agent      string
	Target     string
	TargetType string
	Result     string
	Reason     string
}

type AttestationEvidence struct {
	Evidence  Evidence `json:"evidence"`
	Signature string   `json:"signature,omitempty"`
}

// NotRunWhitelistEntry represents Whitelist Reference Values which where expected from the Evidence but actually not included
type NotRunWhitelistEntry struct {
	Id           string   `json:"id"`
	HashAlg      string   `json:"hashAlg"`
	ExpectedHash []string `json:"expectedHash"`
}

// AbsentWhitelistEntry represents Evidence entries not corresponding to existing Whitelist Reference Values
type AbsentWhitelistEntry struct {
	Id         string `json:"id"`
	HashAlg    string `json:"hashAlg"`
	ActualHash string `json:"actualHash,omitempty"`
}

// MismatchingWhitelistEntry represents Evidence entries whose digest value do not match the actual value stored in the Whitelist Reference Value
type MismatchingWhitelistEntry struct {
	Id           string   `json:"id"`
	HashAlg      string   `json:"hashAlg"`
	ActualHash   string   `json:"actualHash,omitempty"`
	ExpectedHash []string `json:"expectedHash,omitempty"`
}

// ErroredWhitelistEntries aggregate all entries that for their individual reason failed to be correctly evaluated with the Whitelist
type ErroredWhitelistEntries struct {
	NotRunWhitelistEntries      []NotRunWhitelistEntry      `json:"notRunWhitelistEntries,omitempty"`
	AbsentWhitelistEntries      []AbsentWhitelistEntry      `json:"absentWhitelistEntries,omitempty"`
	MismatchingWhitelistEntries []MismatchingWhitelistEntry `json:"mismatchingWhitelistEntries,omitempty"`
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
