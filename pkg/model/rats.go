package model

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/veraison/cmw"
	"time"
)

const (
	CmwCollectionTypeAttestationResult            = "tag:attestation.com,2025:attestation-result"
	CmwCollectionTypeAttestationEvidence          = "tag:attestation.com,2025:attestation-evidence"
	CmwCollectionTypeCredentialActivationEvidence = "tag:attestation.com,2025:credential-activation-evidence"
)

const EATProfile = "tag:github.com,2023:veraison/ear"

const (
	EatJWTMediaType       = "application/eat+jwt"
	EatCWTMediaType       = "application/eat+cwt"
	EatJsonClaimMediaType = "application/eat-ucs+json"
	EatCborClaimMediaType = "application/eat-ucs+cbor"
)

const (
	BootQuoteClaimKey         = "bootQuote"
	IMAMeasurementLogClaimKey = "imaMeasurementLog"
	IMAPcrQuoteClaimKey       = "imaPcrQuote"
)

type StatusLabel int

const (
	SlNone            StatusLabel = iota
	SlAffirming                   = 2
	SlWarning                     = 32
	SlContraindicated             = 96
)

func (sl StatusLabel) String() string {
	switch sl {
	case SlNone:
		return "None"
	case SlAffirming:
		return "Affirming"
	case SlWarning:
		return "Warning"
	case SlContraindicated:
		return "Contraindicated"
	default:
		return "Unknown"
	}
}

type ConceptualMessageType int

const (
	CmReferenceValues ConceptualMessageType = iota
	CmEndorsements
	CmEvidence
	CmAttestationResults
)

func (cm ConceptualMessageType) String() string {
	switch cm {
	case CmReferenceValues:
		return "ReferenceValues"
	case CmEndorsements:
		return "Endorsements"
	case CmEvidence:
		return "Evidence"
	case CmAttestationResults:
		return "AttestationResults"
	default:
		return "Unknown"
	}
}

type IndividualResultType int

const (
	IrSuccess IndividualResultType = 1
	IrFail                         = 2
	IrNotRun                       = 3
	IrAbsent                       = 4
)

func (ir IndividualResultType) String() string {
	switch ir {
	case IrSuccess:
		return "Success"
	case IrFail:
		return "Fail"
	case IrNotRun:
		return "NotRun"
	case IrAbsent:
		return "Absent"
	default:
		return "Unknown"
	}
}

type IndividualResult struct {
	Id     string               `json:"id"`
	Result IndividualResultType `json:"result"`
}

type EAT struct {
	Nonce   string             `json:"nonce"`
	Measres []IndividualResult `json:"measres"`
}

type EARAppraisal struct {
	Status StatusLabel `json:"ear.status"`
}

type EAR struct {
	EATProfile      string                  `json:"eat_profile"`
	Iat             int64                   `json:"iat"`
	VerifierIdLabel string                  `json:"verifier-id-label"`
	EarRawEvidence  string                  `json:"ear.raw-evidence"`
	Submods         map[string]EARAppraisal `json:"submods"`
}

type RatsAttestationResult struct {
	results *cmw.CMW
}

type RatsEvidence struct {
	claims *cmw.CMW
}

func NewEAR(eat *EAT, verifierId string, submods map[string]EARAppraisal) (*EAR, error) {
	rawEat, err := json.Marshal(eat)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EAT: %w", err)
	}

	return &EAR{
		EATProfile:      EATProfile,
		Iat:             time.Now().Unix(),
		VerifierIdLabel: verifierId,
		EarRawEvidence:  base64.URLEncoding.EncodeToString(rawEat),
		Submods:         submods,
	}, nil
}

func (ar *RatsAttestationResult) toJWT(signingMethod jwt.SigningMethod, signingKey any, issuer string, minuteExp int) (string, error) {
	rawCmw, err := ar.ToJSON()
	if err != nil {
		return "", fmt.Errorf("failed to marshal cmw: %w", err)
	}
	token := jwt.NewWithClaims(signingMethod, jwt.MapClaims{
		"cmw": rawCmw,
		"iss": issuer,
		"exp": time.Now().Add(time.Minute * time.Duration(minuteExp)).Unix(),
		"nbf": time.Now().Unix(),
	})
	signedToken, err := token.SignedString(signingKey)
	if err != nil {
		return "", fmt.Errorf("failed to sign attestation result jwt: %w", err)
	}
	return signedToken, nil
}

func (ar *RatsAttestationResult) FromJWT(jwtString string, signingMethod jwt.SigningMethod, signingKey any) error {
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != signingMethod {
			return nil, fmt.Errorf("failed to parse attestation result jwt; unexpected signing method: %v", token.Header["alg"])
		}
		return signingKey, nil
	})

	if err != nil {
		return fmt.Errorf("failed to parse attestation result jwt: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if _, exists := claims["cmw"]; !exists {
			return fmt.Errorf("failed to parse attestation result jwt; claims missing 'cmw'")
		}
		err = ar.FromJSON(claims["cmw"].([]byte))
		if err != nil {
			return fmt.Errorf("failed to parse attestation result jwt: %w", err)
		}
		return nil
	}
	return fmt.Errorf("failed to parse attestation result jwt: token invalid")
}

func (ar *RatsAttestationResult) ToJSON() ([]byte, error) {
	attestationResultJSON, err := ar.results.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results of attestation result: %w", err)
	}
	return attestationResultJSON, nil
}

func (ar *RatsAttestationResult) FromJSON(attestationResultJSON []byte) error {
	err := ar.results.UnmarshalJSON(attestationResultJSON)
	if err != nil {
		return fmt.Errorf("failed to unmarshal results into attestation result: %w", err)
	}
	return nil
}

func NewAttestationResult() (*RatsAttestationResult, error) {
	results, err := cmw.NewCollection(CmwCollectionTypeAttestationResult)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize attestation result: %w", err)
	}
	return &RatsAttestationResult{results: results}, nil
}

func NewEvidence() (*RatsEvidence, error) {
	claims, err := cmw.NewCollection(CmwCollectionTypeAttestationEvidence)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize attestation evidence: %w", err)
	}
	return &RatsEvidence{claims: claims}, nil
}

func NewClaim(mediaType any, value []byte, indicators ...cmw.Indicator) (*cmw.CMW, error) {
	claim, err := cmw.NewMonad(mediaType, value, indicators...)
	if err != nil {
		return nil, fmt.Errorf("failed to create claim: %w", err)
	}
	return claim, nil
}

func (e *RatsEvidence) AddClaim(key any, claim *cmw.CMW) error {
	err := e.claims.AddCollectionItem(key, claim)
	if err != nil {
		return fmt.Errorf("failed to add claim to attestation evidence: %w", err)
	}
	return nil
}

func (e *RatsEvidence) GetClaim(key any) (*cmw.CMW, error) {
	claim, err := e.claims.GetCollectionItem(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get claim from attestation evidence: %w", err)
	}
	return claim, nil
}

func (e *RatsEvidence) ToJSON() ([]byte, error) {
	evidenceJSON, err := e.claims.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims of attestation evidence: %w", err)
	}
	return evidenceJSON, nil
}

func (e *RatsEvidence) FromJSON(jsonEvidence []byte) error {
	err := e.claims.UnmarshalJSON(jsonEvidence)
	if err != nil {
		return fmt.Errorf("failed to unmarshal claims into attestation evidence: %w", err)
	}
	return nil
}
