package model

// shared struct definitions

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

type TPMVendor struct {
	VendorID      string `json:"vendorId,omitempty"`
	Name          string `json:"vendorName"`
	TCGIdentifier string `json:"TCGIdentifier"`
}

type Evidence struct {
	PodName        string `json:"podName"`
	PodUid         string `json:"podUid"`
	TenantId       string `json:"tenantId"`
	Quote          string `json:"quote,omitempty"`
	MeasurementLog string `json:"measurementLog"`
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
}

type PodResult struct {
	Target string
	Result PodStatusType
	Reason string
}

func (p PodResult) GetKind() TargetType { return PodTarget }

type NodeResult struct {
	Target string
	Result NodeStatusType
	Reason string
}

func (n NodeResult) GetKind() TargetType { return NodeTarget }

type AttestationResult struct {
	Agent  string
	Result TargetResult
}

type AttestationEvidence struct {
	Evidence  Evidence `json:"evidence"`
	Signature string   `json:"signature,omitempty"`
}
