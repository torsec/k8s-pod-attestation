package registrar

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
	registrarHost         string
	registrarPort         int32
	invokerTlsCertificate *x509.Certificate
}

func (c *Client) Init(registrarHost string, registrarPort int32, invokerTlsCertificate *x509.Certificate) {
	c.registrarHost = registrarHost
	c.registrarPort = registrarPort
	c.invokerTlsCertificate = invokerTlsCertificate
}

// Exposed endpoints

// VerifyTenantSignature verifies the provided signature by contacting Server API
func (c *Client) VerifyTenantSignature(verifySignatureRequest *model.VerifySignatureRequest) (*model.RegistrarResponse, error) {
	registrarURL := fmt.Sprintf("http://%s:%d%s", c.registrarHost, c.registrarPort, TenantVerifySignatureUrl)

	jsonPayload, err := json.Marshal(verifySignatureRequest)
	if err != nil {
		return nil, err
	}

	resp, err := http.Post(registrarURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, err
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

	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode signature verification response: %v", err)
	}
	return &registrarResponse, nil
}

// VerifyEKCertificate verifies provided Endorsement Key certificate by rebuilding the certificate chain with the TPM manufacturer intermediate and root CAs
func (c *Client) VerifyEKCertificate(EKCertcheckRequest model.VerifyTPMEKCertificateRequest) (*model.RegistrarResponse, error) {
	registrarCertificateValidateURL := fmt.Sprintf("http://%s:%d%s", c.registrarHost, c.registrarPort, WorkerVerifyEkCertUrl)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(EKCertcheckRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal EK Certificate check request: %v", err)
	}

	// Make the POST request to the agent
	resp, err := http.Post(registrarCertificateValidateURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return nil, fmt.Errorf("failed to send EK Certificate check request: %v", err)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Read response body
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode endorsement key verification response: %v", err)
	}
	return &registrarResponse, nil
}

// Create a new worker in the registrar

func (c *Client) CreateWorker(workerNode *model.WorkerNode) (*model.RegistrarResponse, error) {
	createWorkerURL := fmt.Sprintf("http://%s:%d%s", c.registrarHost, c.registrarPort, WorkerCreateUrl)

	jsonData, err := json.Marshal(workerNode)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal worker data: %v", err)
	}

	resp, err := http.Post(createWorkerURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create worker: %v", err)
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

	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode created worker response: %v", err)
	}
	return &registrarResponse, nil
}

func (c *Client) RemoveWorker(workerName string) (*model.RegistrarResponse, error) {
	registrarWorkerDeletionURL := fmt.Sprintf("http://%s:%d%s?name=%s", c.registrarHost, c.registrarPort, WorkerDeleteByName, workerName)

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodDelete, registrarWorkerDeletionURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to send worker remove request: %v", err)
	}

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send worker remove request: %v", err)
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

	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode worker remove response: %v", err)
	}

	return &registrarResponse, nil
}

func (c *Client) GetWorkerIdByName(nodeName string) (*model.RegistrarResponse, error) {
	registrarSearchWorkerURL := fmt.Sprintf("http://%s:%d%s?name=%s", c.registrarHost, c.registrarPort, WorkerGetIdByNameUrl, nodeName)

	resp, err := http.Get(registrarSearchWorkerURL)
	if err != nil {
		return nil, fmt.Errorf("failed to get worker node id from registrar: %v", err)
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

	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode get worker response: %v", err.Error())
	}

	return &registrarResponse, nil
}

func (c *Client) StoreTPMVendor(tpmVendor *model.TPMVendor) (*model.RegistrarResponse, error) {
	registrarURL := fmt.Sprintf("http://%s:%d%s", c.registrarHost, c.registrarPort, StoreTPMVendorUrl)
	jsonData, err := json.Marshal(tpmVendor)

	if err != nil {
		return nil, fmt.Errorf("failed to marshal TPM Vendor data: %v", err)
	}

	resp, err := http.Post(registrarURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send store TPM Vendor request: %v", err)
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

	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode store TPM Vendor response: %v", err)
	}
	return &registrarResponse, nil
}

func (c *Client) StoreTPMCaCertificate(certificate *TPMCACertificate) (*model.RegistrarResponse, error) {
	registrarURL := fmt.Sprintf("http://%s:%d%s", c.registrarHost, c.registrarPort, StoreTPMCaCertificateUrl)
	jsonData, err := json.Marshal(certificate)

	if err != nil {
		return nil, fmt.Errorf("failed to marshal certificate data: %v", err)
	}

	resp, err := http.Post(registrarURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send store TPM CA Certificate request: %v", err)
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

	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode store TPM CA Certificate response: %v", err)
	}
	return &registrarResponse, nil
}

// GetTenantIdByName Get Tenant Info from Server
func (c *Client) GetTenantIdByName(tenantName string) (*model.RegistrarResponse, error) {
	registrarURL := fmt.Sprintf("http://%s:%d%s?name=%s", c.registrarHost, c.registrarPort, TenantGetIdByNameUrl, tenantName)
	resp, err := http.Get(registrarURL)
	if err != nil {
		return nil, fmt.Errorf("failed to retrieve Tenant info: %v", err.Error())
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

	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode get tenant response: %v", err.Error())
	}
	return &registrarResponse, nil
}

// VerifyWorkerSignature verifies the provided signature by contacting Server API
func (c *Client) VerifyWorkerSignature(verifySignatureRequest *model.VerifySignatureRequest) (*model.RegistrarResponse, error) {
	registrarURL := fmt.Sprintf("http://%s:%d%s", c.registrarHost, c.registrarPort, WorkerVerifySignatureUrl)

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
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Parse the response into the RegistrarResponse struct
	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode signature verification response: %v", err.Error())
	}

	// Verify if the status and message indicate success
	return &registrarResponse, nil
}

func (c *Client) CreateTenant(tenant *Tenant) (*model.RegistrarResponse, error) {
	createTenantURL := fmt.Sprintf("http://%s:%d%s", c.registrarHost, c.registrarPort, TenantCreateUrl)

	jsonData, err := json.Marshal(tenant)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal tenant data: %v", err)
	}

	resp, err := http.Post(createTenantURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create tenant: %v", err)
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

	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode created tenant response: %v", err)
	}
	return &registrarResponse, nil
}

func (c *Client) DeleteTenantByName(tenantName string) (*model.RegistrarResponse, error) {
	deleteTenantURL := fmt.Sprintf("http://%s:%d%s?name=%s", c.registrarHost, c.registrarPort, TenantDeleteByNameUrl, tenantName)

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodDelete, deleteTenantURL, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to send tenant remove request: %v", err)
	}

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send tenant remove request: %v", err)
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

	var registrarResponse model.RegistrarResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&registrarResponse); err != nil {
		return nil, fmt.Errorf("failed to decode tenant remove response: %v", err)
	}

	return &registrarResponse, nil
}
