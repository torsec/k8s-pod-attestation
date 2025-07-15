package model

import (
	"fmt"
	"github.com/veraison/cmw"
)

const CmwCollectionTypeAttestationEvidence = "tag:attestation.com,2025:attestation-evidence"
const CmwCollectionTypeCredentialActivationEvidence = "tag:attestation.com,2025:credential-activation-evidence"

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

type Evidence struct {
	claims *cmw.CMW
}

func NewEvidence(cmwCollectionType string) (*Evidence, error) {
	claims, err := cmw.NewCollection(cmwCollectionType)
	if err != nil {
		return nil, fmt.Errorf("failed to initialize attestation evidence: %w", err)
	}
	return &Evidence{claims: claims}, nil
}

func NewClaim(mediaType any, value []byte, indicators ...cmw.Indicator) (*cmw.CMW, error) {
	claim, err := cmw.NewMonad(mediaType, value, indicators...)
	if err != nil {
		return nil, fmt.Errorf("failed to create claim: %w", err)
	}
	return claim, nil
}

func (e *Evidence) AddClaim(key any, claim *cmw.CMW) error {
	err := e.claims.AddCollectionItem(key, claim)
	if err != nil {
		return fmt.Errorf("failed to add claim to attestation evidence: %w", err)
	}
	return nil
}

func (e *Evidence) GetClaim(key any) (*cmw.CMW, error) {
	claim, err := e.claims.GetCollectionItem(key)
	if err != nil {
		return nil, fmt.Errorf("failed to get claim from attestation evidence: %w", err)
	}
	return claim, nil
}

func (e *Evidence) ToJSON() ([]byte, error) {
	evidenceJSON, err := e.claims.MarshalJSON()
	if err != nil {
		return nil, fmt.Errorf("failed to marshal claims of attestation evidence: %w", err)
	}
	return evidenceJSON, nil
}

func (e *Evidence) FromJSON(jsonEvidence []byte) error {
	err := e.claims.UnmarshalJSON(jsonEvidence)
	if err != nil {
		return fmt.Errorf("failed to unmarshal claims into attestation evidence: %w", err)
	}
	return nil
}
