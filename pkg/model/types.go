package model

// shared struct definitions

type PodFileWhitelist struct {
	FilePath     string              `json:"filePath" bson:"filePath"`
	ValidDigests map[string][]string `json:"validDigests" bson:"validDigests"` // Hash algorithm as the key
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

// PCRSet represents a PCR bank in the TPM. A bank is a set of PCRs using the same cryptographic hash algorithm.
// This enables the TPM to keep separate measurements for different algorithms simultaneously.
// Hash: Hash algorithm used by the bank (e.g., SHA256)
// PCRs: Map of PCR index to its stored value
type PCRSet struct {
	Hash int               `json:"hash"`
	PCRs map[string]string `json:"pcrs"`
}

type Evidence struct {
	PodName        string `json:"podName"`
	PodUid         string `json:"podUid"`
	TenantId       string `json:"tenantId"`
	Quote          []byte `json:"quote,omitempty"`
	MeasurementLog []byte `json:"measurementLog,omitempty"`
	Signature      []byte `json:"signature,omitempty"`
}

type IMAEntry struct {
	FilePath string `json:"filePath"`
	FileHash string `json:"fileHash"`
}

// PodStatusType represents pod security status possible values
type PodStatusType string

const (
	NewPodStatus       PodStatusType = "NEW"
	TrustedPodStatus   PodStatusType = "TRUSTED"
	UntrustedPodStatus PodStatusType = "UNTRUSTED"
	UnknownPodStatus   PodStatusType = "UNKNOWN"
	DeletedPodStatus   PodStatusType = "DELETED"
)

func (p PodStatusType) IsValidPodStatus() bool {
	switch p {
	case TrustedPodStatus, UntrustedPodStatus, UnknownPodStatus, DeletedPodStatus, NewPodStatus:
		return true
	default:
		return false
	}
}

func (p PodStatusType) ToString() string {
	if p.IsValidPodStatus() {
		return string(p)
	}
	return "INVALID_POD_STATUS"
}

type TargetType string

const (
	PodTarget  TargetType = "Pod"
	NodeTarget TargetType = "Node"
)

type NodeStatusType string

const (
	TrustedNodeStatus   NodeStatusType = "TRUSTED"
	UntrustedNodeStatus NodeStatusType = "UNTRUSTED"
	UnknownNodeStatus   NodeStatusType = "UNKNOWN"
	DeletedNodeStatus   NodeStatusType = "DELETED"
)

func (n NodeStatusType) IsValidNodeStatus() bool {
	switch n {
	case TrustedNodeStatus, UntrustedNodeStatus, UnknownNodeStatus, DeletedNodeStatus:
		return true
	default:
		return false
	}
}

func (n NodeStatusType) ToString() string {
	if n.IsValidNodeStatus() {
		return string(n)
	}
	return "INVALID_NODE_STATUS"
}

type TargetResult interface {
	GetKind() TargetType
	GetName() string
	GetResult() string
}

type PodResult struct {
	Name     string
	TenantId string
	Result   PodStatusType
	Reason   string
}

func (p PodResult) GetKind() TargetType { return PodTarget }
func (p PodResult) GetName() string     { return p.Name }
func (p PodResult) GetResult() string   { return p.Result.ToString() }

type NodeResult struct {
	Name   string
	Result NodeStatusType
	Reason string
}

func (n NodeResult) GetKind() TargetType { return NodeTarget }
func (n NodeResult) GetName() string     { return n.Name }
func (n NodeResult) GetResult() string   { return n.Result.ToString() }

type AttestationResult struct {
	Agent  string
	Result TargetResult
}

type AgentConfig struct {
	TPMPath                    string `json:"TPMPath"`
	IMAMeasurementLogMountPath string `json:"IMAMeasurementLogMountPath"`
	IMAMeasurementLogPath      string `json:"IMAMeasurementLogPath"`
	ImageName                  string `json:"imageName"`
	AgentPort                  int32  `json:"agentPort"`
	AgentNodePortAllocation    int32  `json:"agentNodePortAllocation"`
}
