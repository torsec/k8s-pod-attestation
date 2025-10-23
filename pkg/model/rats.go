package model

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/golang-jwt/jwt/v5"
	"github.com/veraison/cmw"
	"time"
)

type CmwCollectionType string

const (
	CmwCollectionTypeAttestationResult            CmwCollectionType = "tag:attestation.com,2025:attestation-result"
	CmwCollectionTypeAttestationEvidence          CmwCollectionType = "tag:attestation.com,2025:attestation-evidence"
	CmwCollectionTypeCredentialActivationEvidence CmwCollectionType = "tag:attestation.com,2025:credential-activation-evidence"
)

func (ct CmwCollectionType) String() string {
	switch ct {
	case CmwCollectionTypeAttestationResult:
		return "tag:attestation.com,2025:attestation-result"
	case CmwCollectionTypeAttestationEvidence:
		return "tag:attestation.com,2025:attestation-evidence"
	case CmwCollectionTypeCredentialActivationEvidence:
		return "tag:attestation.com,2025:credential-activation-evidence"
	default:
		return "unknown_collection_type"
	}
}

const EATProfile = "tag:github.com,2023:veraison/ear"

type MediaType string

const (
	EatJWTMediaType       MediaType = "application/eat+jwt"
	EatCWTMediaType       MediaType = "application/eat+cwt"
	EatJsonClaimMediaType MediaType = "application/eat-ucs+json"
	EatCborClaimMediaType MediaType = "application/eat-ucs+cbor"
)

func (mt MediaType) String() string {
	switch mt {
	case EatJWTMediaType:
		return "application/eat+jwt"
	case EatCWTMediaType:
		return "application/eat+cwt"
	case EatJsonClaimMediaType:
		return "application/eat-ucs+json"
	case EatCborClaimMediaType:
		return "application/eat-ucs+cbor"
	default:
		return "unknown_media_type"
	}
}

const (
	BootQuoteClaimKey                = "bootQuote"
	IMAMeasurementLogClaimKey        = "imaMeasurementLog"
	IMAPcrQuoteClaimKey              = "imaPcrQuote"
	CredentialActivationHMACClaimKey = "credentialActivationHMAC"
)

// Indicator https://www.ietf.org/archive/id/draft-ietf-rats-msg-wrap-11.html#section-10.4.2
type Indicator uint

const (
	ReferenceValuesIndicator Indicator = 1 << iota
	EndorsementsIndicator
	EvidenceIndicator
	AttestationResultsIndicator
	TrustAnchorsIndicator
)

func (indicator Indicator) ToCmwIndicator() cmw.Indicator {
	return cmw.Indicator(indicator)
}

func (indicator Indicator) String() string {
	switch indicator {
	case ReferenceValuesIndicator:
		return "ReferenceValues"
	case EndorsementsIndicator:
		return "Endorsements"
	case EvidenceIndicator:
		return "Evidence"
	case AttestationResultsIndicator:
		return "AttestationResults"
	case TrustAnchorsIndicator:
		return "TrustAnchors"
	default:
		return "unknown_indicator"
	}
}

type StatusLabel uint

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
		return "unknown_status_label"
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

func NewCmwItem(mediaType MediaType, value []byte, indicators ...Indicator) (*cmw.CMW, error) {
	var cmwIndicators []cmw.Indicator
	for _, indicator := range indicators {
		cmwIndicators = append(cmwIndicators, indicator.ToCmwIndicator())
	}
	cmwItem, err := cmw.NewMonad(mediaType.String(), value, cmwIndicators...)
	if err != nil {
		return nil, fmt.Errorf("failed to create cmw: %w", err)
	}
	return cmwItem, nil
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

func (ear *EAR) ToJSON() ([]byte, error) {
	earJSON, err := json.Marshal(ear)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EAR: %w", err)
	}
	return earJSON, nil
}

func EARFromJSON(earJSON []byte) (*EAR, error) {
	ear := &EAR{}
	err := json.Unmarshal(earJSON, ear)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal EAR: %w", err)
	}
	return ear, nil
}

func (ar *RatsAttestationResult) ToJWT(signingMethod jwt.SigningMethod, signingKey any, issuer string, minuteExp int) (string, error) {
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

func AttestationResultFromJWT(jwtString string, signingMethod jwt.SigningMethod, publicKey any) (*RatsAttestationResult, error) {
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != signingMethod {
			return nil, fmt.Errorf("failed to parse attestation result jwt; unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation result jwt: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if _, exists := claims["cmw"]; !exists {
			return nil, fmt.Errorf("failed to parse attestation result jwt; claims missing 'cmw'")
		}
		decodedCmw, err := base64.StdEncoding.DecodeString(claims["cmw"].(string))
		if err != nil {
			return nil, fmt.Errorf("failed to decode evidence jwt; failed to parse 'cmw' claim from base64: %w", err)
		}

		ar, err := AttestationResultFromJSON(decodedCmw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse attestation result jwt: %w", err)
		}
		return ar, nil
	}
	return nil, fmt.Errorf("failed to parse attestation result jwt: token invalid")
}

func (ar *RatsAttestationResult) ToJSON() ([]byte, error) {
	attestationResultJSON, err := ar.results.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal results of attestation result: %w", err)
	}
	return attestationResultJSON, nil
}

func AttestationResultFromJSON(attestationResultJSON []byte) (*RatsAttestationResult, error) {
	results := &cmw.CMW{}
	err := results.UnmarshalJSON(attestationResultJSON)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal results into attestation result: %w", err)
	}
	return &RatsAttestationResult{results: results}, nil
}

func (ar *RatsAttestationResult) AddResult(key any, value []byte, mediaType MediaType) error {
	cmwItem, err := cmw.NewMonad(mediaType.String(), value, AttestationResultsIndicator.ToCmwIndicator())
	if err != nil {
		return fmt.Errorf("failed to create cmw for attestation result: %w", err)
	}
	err = ar.results.AddCollectionItem(key, cmwItem)
	if err != nil {
		return fmt.Errorf("failed to add result to attestation result: %w", err)
	}
	return nil
}

func (ar *RatsAttestationResult) AddCmwResult(key any, result *cmw.CMW) error {
	resultType, err := result.GetMonadIndicator()
	if err != nil {
		return fmt.Errorf("failed to create cmw for attestation result: %w", err)
	}

	if resultType != AttestationResultsIndicator.ToCmwIndicator() {
		return fmt.Errorf("claim monad type is not '%s'", AttestationResultsIndicator.String())
	}

	err = ar.results.AddCollectionItem(key, result)
	if err != nil {
		return fmt.Errorf("failed to add result to attestation result: %w", err)
	}
	return nil
}

func (ar *RatsAttestationResult) GetResult(key any) ([]byte, error) {
	result, err := ar.results.GetCollectionItem(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get result from attestation result: %w", err)
	}
	val, err := result.GetMonadValue()
	if err != nil {
		return nil, fmt.Errorf("failed to get result value from attestation result: %w", err)
	}
	return val, nil
}

func (ar *RatsAttestationResult) GetCmwResult(key any) (*cmw.CMW, error) {
	result, err := ar.results.GetCollectionItem(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get cmw result from attestation evidence: %w", err)
	}
	return result, nil
}

func NewAttestationResult(attestationResultType CmwCollectionType) (*RatsAttestationResult, error) {
	results, err := cmw.NewCollection(attestationResultType.String())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize attestation result: %w", err)
	}
	return &RatsAttestationResult{results: results}, nil
}

// Evidence

func NewEvidence(evidenceType CmwCollectionType) (*RatsEvidence, error) {
	claims, err := cmw.NewCollection(evidenceType.String())
	if err != nil {
		return nil, fmt.Errorf("failed to initialize attestation evidence: %w", err)
	}
	return &RatsEvidence{claims: claims}, nil
}

func (e *RatsEvidence) AddClaim(key any, value []byte, mediaType MediaType) error {
	cmwItem, err := cmw.NewMonad(mediaType.String(), value, EvidenceIndicator.ToCmwIndicator())
	if err != nil {
		return fmt.Errorf("failed to create cmw for claim: %w", err)
	}
	err = e.claims.AddCollectionItem(key, cmwItem)
	if err != nil {
		return fmt.Errorf("failed to add claim to attestation evidence: %w", err)
	}
	return nil
}

func (e *RatsEvidence) AddCmwClaim(key any, claim *cmw.CMW) error {
	monadType, err := claim.GetMonadIndicator()
	if err != nil {
		return fmt.Errorf("failed to create cmw for claim: %w", err)
	}

	if monadType != EvidenceIndicator.ToCmwIndicator() {
		return fmt.Errorf("claim monad type is not '%s'", EvidenceIndicator.String())
	}

	err = e.claims.AddCollectionItem(key, claim)
	if err != nil {
		return fmt.Errorf("failed to add claim to attestation evidence: %w", err)
	}
	return nil
}

func (e *RatsEvidence) GetClaim(key any) ([]byte, error) {
	claim, err := e.claims.GetCollectionItem(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get claim from attestation evidence: %w", err)
	}
	val, err := claim.GetMonadValue()
	if err != nil {
		return nil, fmt.Errorf("failed to get claim value from attestation evidence: %w", err)
	}
	return val, nil
}

func (e *RatsEvidence) GetClaims() (map[any][]byte, error) {
	return nil, nil
}

func (e *RatsEvidence) GetCmwClaim(key any) (*cmw.CMW, error) {
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

func EvidenceFromJSON(jsonEvidence []byte) (*RatsEvidence, error) {
	claims := &cmw.CMW{}
	err := claims.UnmarshalJSON(jsonEvidence)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal claims into attestation evidence: %w", err)
	}
	return &RatsEvidence{claims: claims}, nil
}

func (e *RatsEvidence) ToJWT(signingMethod jwt.SigningMethod, signingKey any, issuer string, minuteExp int) (string, error) {
	rawCmw, err := e.ToJSON()
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
		return "", fmt.Errorf("failed to sign evidence jwt: %w", err)
	}
	return signedToken, nil
}

func EvidenceFromJWT(jwtString string, signingMethod jwt.SigningMethod, publicKey any) (*RatsEvidence, error) {
	token, err := jwt.Parse(jwtString, func(token *jwt.Token) (interface{}, error) {
		if token.Method != signingMethod {
			return nil, fmt.Errorf("failed to parse evidence jwt; unexpected signing method: %v", token.Header["alg"])
		}
		return publicKey, nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to parse evidence jwt: %w", err)
	}

	if claims, ok := token.Claims.(jwt.MapClaims); ok && token.Valid {
		if _, exists := claims["cmw"]; !exists {
			return nil, fmt.Errorf("failed to parse evidence jwt; claims missing 'cmw'")
		}
		decodedCmw, err := base64.StdEncoding.DecodeString(claims["cmw"].(string))
		if err != nil {
			return nil, fmt.Errorf("failed to decode evidence jwt; failed to parse 'cmw' claim from base64: %w", err)
		}
		e, err := EvidenceFromJSON(decodedCmw)
		if err != nil {
			return nil, fmt.Errorf("failed to parse evidence jwt: %w", err)
		}
		return e, nil
	}
	return nil, fmt.Errorf("failed to parse evidence jwt: token invalid")
}
