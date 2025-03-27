package agent

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"io"
	"net/http"
)

type Client struct {
	agentHost             string
	agentPort             int
	invokerTlsCertificate *x509.Certificate
}

func (c *Client) Init(agentHost string, agentPort int, invokerTlsCertificate *x509.Certificate) {
	c.agentHost = agentHost
	c.agentPort = agentPort
	c.invokerTlsCertificate = invokerTlsCertificate
}

func (c *Client) WorkerRegistrationCredentials() (*model.WorkerCredentialsResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.agentHost, c.agentPort, GetWorkerRegistrationCredentialsUrl)
	resp, err := http.Get(completeUrl)
	if err != nil {
		return nil, fmt.Errorf("failed to get Worker identification data: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	var credentialsResponse *model.WorkerCredentialsResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(credentialsResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return credentialsResponse, nil
}

func (c *Client) WorkerRegistrationChallenge(workerWhitelistCheckRequest *model.WorkerWhitelistCheckRequest) (*model.WorkerChallengeResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.agentHost, c.agentPort, WorkerRegistrationChallengeUrl)
	jsonData, err := json.Marshal(workerWhitelistCheckRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal challenge payload: %v", err)
	}

	// Send HTTP POST request
	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send challenge request: %v", err)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	// Decode the response JSON into the WorkerChallengeResponse struct
	var challengeResponse *model.WorkerChallengeResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(challengeResponse); err != nil {
		return nil, fmt.Errorf("failed to decode challenge response: %v", err)
	}

	return challengeResponse, nil
}

func (c *Client) WorkerRegistrationAcknowledge(acknowledge *model.RegistrationAcknowledge) (*model.WorkerRegistrationConfirm, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.agentHost, c.agentPort, AcknowledgeRegistrationUrl)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(acknowledge)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal Registration acknowledge request: %v", err)
	}

	// Make the POST request to the agent
	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to send Registration acknowledge request: %v", err)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	var registrationConfirm *model.WorkerRegistrationConfirm
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(registrationConfirm); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return registrationConfirm, nil
}

func (c *Client) PodAttestation(attestationRequest *model.AttestationRequest) (*model.AttestationResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.agentHost, c.agentPort, PodAttestationUrl)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(attestationRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal attestation request: %v", err)
	}

	// Make the POST request to the agent
	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to send pod attestation request: %v", err)
	}

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	var attestationResponse *model.AttestationResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(attestationResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return attestationResponse, nil
}
