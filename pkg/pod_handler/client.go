package pod_handler

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
	podHandlerHost        string
	podHandlerPort        int
	invokerTlsCertificate *x509.Certificate
}

func (c *Client) Init(podHandlerHost string, podHandlerPort int, invokerTlsCertificate *x509.Certificate) {
	c.podHandlerHost = podHandlerHost
	c.podHandlerPort = podHandlerPort
	c.invokerTlsCertificate = invokerTlsCertificate
}

func (c *Client) SecurePodDeployment(podDeploymentRequest model.PodDeploymentRequest) (*model.PodHandlerResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.podHandlerHost, c.podHandlerPort, DeployPodUrl)

	jsonData, err := json.Marshal(podDeploymentRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pod deployment request: %v", err)
	}

	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send pod deployment request: %v", err)
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
	var podHandlerResponse *model.PodHandlerResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(podHandlerResponse); err != nil {
		return nil, fmt.Errorf("failed to decode pod deployment response: %v", err)
	}

	return podHandlerResponse, nil
}

func (c *Client) PodAttestation(podAttestationRequest *model.PodAttestationRequest) (*model.PodHandlerResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.podHandlerHost, c.podHandlerPort, AttestPodUrl)

	jsonData, err := json.Marshal(podAttestationRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pod attestation request: %v", err)
	}

	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonData))
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

	// Decode the response JSON into the WorkerChallengeResponse struct
	var podHandlerResponse *model.PodHandlerResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(podHandlerResponse); err != nil {
		return nil, fmt.Errorf("failed to decode pod attestation response: %v", err)
	}

	return podHandlerResponse, nil
}
