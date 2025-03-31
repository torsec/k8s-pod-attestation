package main

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	apiextensionsv1clientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"log"
	"net/http"
	"os"
	"time"
)

type AttestationRequest struct {
	Nonce     string `json:"nonce"`
	PodName   string `json:"podName"`
	PodUID    string `json:"podUID"`
	TenantId  string `json:"tenantId"`
	Signature string `json:"signature,omitempty"`
}

type RegistrarResponse struct {
	Message string `json:"message"`
	Status  string `json:"status"`
}

type Evidence struct {
	PodName     string `json:"podName"`
	PodUID      string `json:"podUID"`
	TenantId    string `json:"tenantId"`
	WorkerQuote string `json:"workerQuote"`
	WorkerIMA   string `json:"workerIMA"`
}

type AttestationResponse struct {
	Evidence  Evidence `json:"evidence"`
	Signature string   `json:"signature,omitempty"`
}

type InputQuote struct {
	Quote  string `json:"quote"`
	RawSig string `json:"raw_sig"`
	PCRs   PCRSet `json:"pcrs"`
}

// PCRSet represents the PCR values and the hash algorithm used
type PCRSet struct {
	Hash int               `json:"hash"`
	PCRs map[string]string `json:"pcrs"`
}

type IMAEntry struct {
	FilePath string `json:"filePath"`
	FileHash string `json:"fileHash"`
}

type PodWhitelistCheckRequest struct {
	PodImageName   string     `json:"podImageName"`
	PodImageDigest string     `json:"podImageDigest"`
	PodFiles       []IMAEntry `json:"podFiles"`
	HashAlg        string     `json:"hashAlg"` // Include the hash algorithm in the request
}

type ContainerRuntimeCheckRequest struct {
	ContainerRuntimeName         string     `json:"containerRuntimeName"`
	ContainerRuntimeDependencies []IMAEntry `json:"containerRuntimeDependencies"`
	HashAlg                      string     `json:"hashAlg"` // Include the hash algorithm in the request
}

type AttestationResult struct {
	Agent      string
	Target     string
	TargetType string
	Result     string
	Reason     string
}

const COLON_BYTE = byte(58) // ASCII code for ":"
const NULL_BYTE = byte(0)
const containerRuntimeDependencies = "/usr/bin/containerd:/usr/bin/containerd:/usr/lib/systemd/systemd:swapper/0"
const containerRuntimeName = "/usr/bin/containerd-shim-runc-v2"

// Color variables for output
var (
	clientset                    *kubernetes.Clientset
	dynamicClient                dynamic.Interface
	apiExtensionsClient          *apiextensionsv1clientset.Clientset
	registrarHOST                string
	registrarPORT                string
	attestationNamespaces        string
	attestationEnabledNamespaces []string
	whitelistHOST                string
	whitelistPORT                string
	attestationSecret            []byte
	verifierPrivateKey           string
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	registrarHOST = getEnv("REGISTRAR_HOST", "localhost")
	registrarPORT = getEnv("REGISTRAR_PORT", "8080")
	attestationNamespaces = getEnv("ATTESTATION_NAMESPACES", "[\"default\"]")
	whitelistHOST = getEnv("WHITELIST_HOST", "localhost")
	whitelistPORT = getEnv("WHITELIST_PORT", "9090")
	verifierPrivateKey = getEnv("VERIFIER_PRIVATE_KEY", "")
	attestationSecret = []byte(getEnv("ATTESTATION_SECRET", ""))
	// setting namespaces allowed for attestation: only pods deployed within them can be attested
	err := json.Unmarshal([]byte(attestationNamespaces), &attestationEnabledNamespaces)
	if err != nil {
		log.Fatalf("Failed to parse 'ATTESTATION_NAMESPACES' content: %v", err)
	}
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		if key == "ATTESTATION_NAMESPACES" {
			fmt.Printf(yellow.Sprintf("[%s] '%s' environment variable missing: setting default value: ['default']\n", time.Now().Format("02-01-2006 15:04:05"), key))
		}
		return defaultValue
	}
	return value
}

func verifyContainerRuntimeIntegrity(checkRequest ContainerRuntimeCheckRequest) error {
	whitelistProviderWorkerValidateURL := fmt.Sprintf("http://%s:%s/whitelist/container/runtime/check", whitelistHOST, whitelistPORT)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(checkRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal Whitelist check request: %v", err)
	}

	log.Printf(string(jsonPayload))

	// Make the POST request to the agent
	resp, err := http.Post(whitelistProviderWorkerValidateURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send Whitelist check request: %v", err)
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
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Whitelists Provider failed to process check request: %s (status: %d)", string(body), resp.StatusCode)
	}

	return nil
}

// Verify the provided signature by contacting Registrar API
func verifyWorkerSignature(workerName string, message []byte, signature string) (bool, error) {
	registrarURL := fmt.Sprintf("http://%s:%s/worker/verify", registrarHOST, registrarPORT)
	payload := map[string]string{
		"name":      workerName,
		"message":   base64.StdEncoding.EncodeToString(message),
		"signature": signature,
	}

	// Marshal payload to JSON
	jsonPayload, err := json.Marshal(payload)
	if err != nil {
		return false, fmt.Errorf("failed to marshal payload: %v", err)
	}

	// Make POST request to the Registrar API
	resp, err := http.Post(registrarURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return false, fmt.Errorf("failed to send request: %v", err)
	}
	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return false, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the response status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return false, fmt.Errorf("failed to verify signature: %s (status: %d)", string(body), resp.StatusCode)
	}

	// Parse the response into the RegistrarResponse struct
	var registrarResp RegistrarResponse
	if err := json.Unmarshal(body, &registrarResp); err != nil {
		return false, fmt.Errorf("failed to parse response: %v", err)
	}

	// Verify if the status and message indicate success
	return registrarResp.Status == "success" && registrarResp.Message == "Signature verification successful", nil
}

func main() {
	initializeColors()
	loadEnvironmentVariables()
	configureKubernetesClient()

	stopCh := setupSignalHandler()
	deployAttestationRequestCRD()

	watchAttestationRequestCRDChanges(stopCh)

	fmt.Printf(green.Sprintf("Watching Attestation Request CRD changes...\n\n"))
	<-stopCh
}
