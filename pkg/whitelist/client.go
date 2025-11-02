package whitelist

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
	whitelistHost         string
	whitelistPort         int32
	invokerTlsCertificate *x509.Certificate
}

func (c *Client) Init(whitelistHost string, whitelistPort int32, invokerTlsCertificate *x509.Certificate) {
	c.whitelistHost = whitelistHost
	c.whitelistPort = whitelistPort
	c.invokerTlsCertificate = invokerTlsCertificate
}

func (c *Client) CheckWorkerWhitelist(workerWhitelistCheckRequest *model.WorkerWhitelistCheckRequest) (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.whitelistHost, c.whitelistPort, CheckWorkerWhitelistUrl)
	jsonData, err := json.Marshal(workerWhitelistCheckRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal worker whitelist check request: %v", err)
	}

	// Send HTTP POST request
	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send worker whitelist check request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return &whitelistResponse, nil
}

func (c *Client) AppendToWorkerWhitelist(osWhitelist *OsWhitelist) (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.whitelistHost, c.whitelistPort, AppendToWorkerWhitelistUrl)
	jsonData, err := json.Marshal(osWhitelist)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal append worker whitelist request: %v", err)
	}

	// Send HTTP POST request
	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send append worker whitelist request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return &whitelistResponse, nil
}

func (c *Client) DeleteFromWorkerWhitelist(osName string) (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s?osName=%s", c.whitelistHost, c.whitelistPort, DeleteFromWorkerWhitelistUrl, osName)

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodDelete, completeUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to send worker whitelist remove request: %v", err)
	}

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send worker whitelist remove request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &whitelistResponse, nil
}

func (c *Client) DropWorkerWhitelist() (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.whitelistHost, c.whitelistPort, DropWorkerWhitelistUrl)

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodDelete, completeUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to send drop worker whitelist request: %v", err)
	}

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send drop worker whitelist request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &whitelistResponse, nil
}

func (c *Client) CheckPodWhitelist(podWhitelistCheckRequest *model.PodWhitelistCheckRequest) (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.whitelistHost, c.whitelistPort, CheckPodWhitelistUrl)
	jsonData, err := json.Marshal(podWhitelistCheckRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal pod whitelist check request: %v", err)
	}

	// Send HTTP POST request
	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send pod whitelist check request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return &whitelistResponse, nil
}

func (c *Client) AppendImageToPodWhitelist(imageWhitelist *ImageWhitelist) (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.whitelistHost, c.whitelistPort, AppendToPodWhitelistUrl)
	jsonData, err := json.Marshal(imageWhitelist)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal append pod whitelist request: %v", err)
	}

	// Send HTTP POST request
	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send append pod whitelist request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return &whitelistResponse, nil
}

func (c *Client) AppendFilesToImage(appendFilesRequest *model.AppendFilesToImageRequest) (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.whitelistHost, c.whitelistPort, AppendFilesToImageUrl)
	jsonData, err := json.Marshal(appendFilesRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal append files to image request: %v", err)
	}

	// Send HTTP POST request
	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send append files to image request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return &whitelistResponse, nil
}

func (c *Client) DropPodWhitelist() (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.whitelistHost, c.whitelistPort, DropPodWhitelistUrl)

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodDelete, completeUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to send drop pod whitelist request: %v", err)
	}

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send drop pod whitelist request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &whitelistResponse, nil
}

func (c *Client) CheckContainerRuntimeWhitelist(containerRuntimeCheckRequest *model.ContainerRuntimeCheckRequest) (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.whitelistHost, c.whitelistPort, CheckContainerRuntimeWhitelistUrl)
	jsonData, err := json.Marshal(containerRuntimeCheckRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal container runtime whitelist check request: %v", err)
	}

	// Send HTTP POST request
	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send container runtime whitelist check request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return &whitelistResponse, nil
}

func (c *Client) AppendToContainerRuntimeWhitelist(containerRuntimeWhitelist *ContainerRuntimeWhitelist) (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.whitelistHost, c.whitelistPort, AppendToContainerRuntimeWhitelistUrl)
	jsonData, err := json.Marshal(containerRuntimeWhitelist)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal append container runtime whitelist request: %v", err)
	}

	// Send HTTP POST request
	resp, err := http.Post(completeUrl, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send append container runtime whitelist request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return &whitelistResponse, nil
}

func (c *Client) DeleteFromContainerRuntimeWhitelist(containerRuntimeName string) (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s?containerRuntimeName=%s", c.whitelistHost, c.whitelistPort, DeleteFromContainerRuntimeWhitelistUrl, containerRuntimeName)

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodDelete, completeUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to send container runtime whitelist remove request: %v", err)
	}

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send container runtime whitelist remove request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &whitelistResponse, nil
}

func (c *Client) DropContainerRuntimeWhitelist() (*model.WhitelistResponse, error) {
	completeUrl := fmt.Sprintf("http://%s:%d%s", c.whitelistHost, c.whitelistPort, DropContainerRuntimeWhitelistUrl)

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodDelete, completeUrl, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to send drop container runtime whitelist request: %v", err)
	}

	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send drop container runtime whitelist request: %v", err)
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

	var whitelistResponse model.WhitelistResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&whitelistResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: %v", err)
	}

	return &whitelistResponse, nil
}
