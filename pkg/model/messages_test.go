package model

import "testing"

func TestAttestationRequest_Sign(t *testing.T) {
	areq := AttestationRequest{}
	err := areq.Sign(nil, 0)
	if err == nil {
		t.Errorf("Expected error when signing with nil key, got nil")
	}
}
