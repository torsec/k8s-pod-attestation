package registrar

import (
	"bytes"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"io"
	"net/http"
	"time"
)

type Client struct {
	registrarHost  string
	registrarPort  int
	tlsCertificate *x509.Certificate
}

// Exposed endpoints

// Verify the provided signature by contacting Server API
func (c *Client) VerifyTenantSignature(verifySignatureRequest *model.VerifySignatureRequest) (bool, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/tenant/verify", c.registrarHost, c.registrarPort)

	jsonPayload, err := json.Marshal(verifySignatureRequest)
	if err != nil {
		return false, err
	}

	resp, err := http.Post(registrarURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false, err
	}
	defer resp.Body.Close()

	return resp.StatusCode == http.StatusOK, nil
}

func (c *Client) VerifyEKCertificate(EKCertcheckRequest model.VerifyTPMEKCertificateRequest) error {
	registrarCertificateValidateURL := fmt.Sprintf("http://%s:%s/worker/verifyEKCertificate",
		c.registrarHost, c.registrarPort)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(EKCertcheckRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal EK Certificate check request: %v", err)
	}

	// Make the POST request to the agent
	resp, err := http.Post(registrarCertificateValidateURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send EK Certificate check request: %v", err)
	}

	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to validate EK Certificate: %c (status: %d)", string(body), resp.StatusCode)
	}
	return nil
}

// Create a new worker in the registrar

func (c *Client) CreateWorker(workerNode *model.WorkerNode) (*model.NewWorkerResponse, error) {
	createWorkerURL := fmt.Sprintf("http://%s:%s/worker/create", c.registrarHost, c.registrarPort)

	jsonData, err := json.Marshal(workerNode)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal worker data: %v", err)
	}

	resp, err := http.Post(createWorkerURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create worker: %v", err)
	}
	defer resp.Body.Close()

	// Read response body in case of an unexpected status
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected response status when creating worker: %s. Response body: %s", resp.Status, string(body))
	}

	var registrarResponse *model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode created worker response: %v", err)
	}
	return registrarResponse, nil
}

func (c *Client) RemoveWorker(workerName string) error {
	registrarWorkerDeletionURL := fmt.Sprintf("http://%s:%s/worker/deleteByName?name=%s", c.registrarHost, c.registrarPort, workerName)

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodDelete, registrarWorkerDeletionURL, nil)
	if err != nil {
		return fmt.Errorf("error creating worker node removal request: %v", err)

	}

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("error sending worker node removal request: %v", err)

	}

	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("failed to remove worker node from Server: received status code %d", resp.StatusCode)
	}

	fmt.Printf("[%s] worker node: '%s' removed from Server with success\n", time.Now().Format("02-01-2006 15:04:05"), workerName)
	return nil
}

func (c *Client) GetWorkerIdByName(nodeName string) (*model.WorkerIdResponse, error) {
	registrarSearchWorkerURL := fmt.Sprintf("http://%s:%s/worker/getIdByName?name=%s", c.registrarHost, c.registrarPort, nodeName)

	resp, err := http.Get(registrarSearchWorkerURL)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, err
	}

	var workerIdResponse *model.WorkerIdResponse
	if err := json.NewDecoder(resp.Body).Decode(workerIdResponse); err != nil {
		return nil, fmt.Errorf("failed to parse Tenant response: %v", err.Error())
	}

	return workerIdResponse, nil
}

// Get Tenant Info from Server
func (c *Client) GetTenantIdByName(tenantName string) (*model.Tenant, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/tenant/getIdByName?name=%s", c.registrarHost, c.registrarPort, tenantName)
	resp, err := http.Get(registrarURL)
	if err != nil || resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to retrieve Tenant info: %v", err.Error())
	}
	defer resp.Body.Close()

	var tenantResp *model.Tenant
	if err := json.NewDecoder(resp.Body).Decode(tenantResp); err != nil {
		return nil, fmt.Errorf("failed to parse Tenant response: %v", err.Error())
	}
	return tenantResp, nil
}

// Verify the provided signature by contacting Server API
func (c *Client) VerifyWorkerSignature(verifySignatureRequest *model.VerifySignatureRequest) (*model.RegistrarResponse, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/worker/verify", c.registrarHost, c.registrarPort)

	// Marshal payload to JSON
	jsonPayload, err := json.Marshal(verifySignatureRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Make POST request to the Server API
	resp, err := http.Post(registrarURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the response status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("failed to verify signature: %s (status: %d)", string(body), resp.StatusCode)
	}

	// Parse the response into the RegistrarResponse struct
	var registrarResponse *model.RegistrarResponse
	if err := json.Unmarshal(body, registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to parse response: %v", err)
	}

	// Verify if the status and message indicate success
	return registrarResponse, nil
}
