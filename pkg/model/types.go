package model

import (
	"crypto"
	"fmt"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
)

// shared struct definitions

type Measurement struct {
	FilePath string `json:"filePath"`
	FileHash string `json:"fileHash"`
}

type FileWhitelist struct {
	FilePath     string                   `json:"filePath" bson:"filePath"`
	ValidDigests map[crypto.Hash][]string `json:"validDigests" bson:"validDigests"` // Hash algorithm as the key
}

// NotRunEntry represents Whitelist Reference Values which where expected from the Evidence but actually not included
type NotRunEntry struct {
	Id           string      `json:"id"`
	HashAlg      crypto.Hash `json:"hashAlg"`
	ExpectedHash []string    `json:"expectedHash"`
}

// AbsentEntry represents Evidence entries not corresponding to existing Whitelist Reference Values
type AbsentEntry struct {
	Id         string      `json:"id"`
	HashAlg    crypto.Hash `json:"hashAlg"`
	ActualHash string      `json:"actualHash,omitempty"`
}

// MismatchingEntry represents Evidence entries whose digest value do not match the actual value stored in the Whitelist Reference Value
type MismatchingEntry struct {
	Id           string      `json:"id"`
	HashAlg      crypto.Hash `json:"hashAlg"`
	ActualHash   string      `json:"actualHash,omitempty"`
	ExpectedHash []string    `json:"expectedHash,omitempty"`
}

// ErroredEntries aggregate all entries that for their individual reason failed to be correctly evaluated with the Whitelist
type ErroredEntries struct {
	NotRun      []NotRunEntry      `json:"notRun,omitempty"`
	Absent      []AbsentEntry      `json:"absent,omitempty"`
	Mismatching []MismatchingEntry `json:"mismatching,omitempty"`
}

type WorkerNode struct {
	WorkerId string `json:"workerId"`
	Name     string `json:"name"`
	AIK      string `json:"AIK"`
}

type Signature struct {
	RawSignature []byte      `json:"rawSignature,omitempty"`
	HashAlg      crypto.Hash `json:"hashAlg"`
}

func (s *Signature) HashToString() string {
	return s.HashAlg.String()
}

func (s *Signature) Valid() bool {
	return len(s.RawSignature) > 0 && s.HashAlg != crypto.Hash(0)
}

func (s *Signature) Sign(privateKey crypto.PrivateKey, msg []byte) error {
	sig, err := cryptoUtils.SignMessage(privateKey, msg, s.HashAlg)
	if err != nil {
		return fmt.Errorf("failed to sign message: %w", err)
	}
	s.RawSignature = sig
	return nil
}

func (s *Signature) Verify(publicKey crypto.PublicKey, msg []byte) error {
	return cryptoUtils.VerifyMessage(publicKey, msg, s.RawSignature, s.HashAlg)
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
