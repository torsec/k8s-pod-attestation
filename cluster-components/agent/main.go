package main

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"io"
	"log"
	"net/http"
	"os"
)

var (
	agentPORT             string
	workerId              string
	TPMPath               string
	IMAMeasurementLogPath string
)

// TEST PURPOSE
var (
	verifierPublicKey = `-----BEGIN PUBLIC KEY-----
MIIBIjANBgkqhkiG9w0BAQEFAAOCAQ8AMIIBCgKCAQEAuoi/38EDObItiLd1Q8Cy
XsPaHjOreYqVJYEO4NfCZR2H01LXrdj/LcpyrB1rKBc4UWI8lroSdhjMJxC62372
WvDk9cD5k+iyPwdM+EggpiRfEmHWF3zob8junyWHW6JInf0+AGhbKgBfMXo9PvAn
r5CVeqp2BrstdZtrWVRuQAKip9c7hl+mHODkE5yb0InHyRe5WWr5P7wtXtAPM6SO
8dVk/QWXdsB9rsb+Ejy4LHSIUpHUOZO8LvGD1rVLO82H4EUXKBFeiOEJjly4HOkv
mFe/c/Cma1pM+702X6ULf0/BIMJkWzD3INdLtk8FE8rIxrrMSnDtmWw9BgGdsDgk
pQIDAQAB
-----END PUBLIC KEY-----`
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	agentPORT = getEnv("AGENT_PORT", "8080")
	TPMPath = getEnv("TPM_PATH", "simulator")
	IMAMeasurementLogPath = getEnv("IMA_PATH", "/root/ascii_runtime_measurements")
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func podAttestation(c *gin.Context) {
	var attestationRequest AttestationRequest

	// Bind the JSON request body to the struct
	if err := c.BindJSON(&attestationRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request payload",
			"status":  "error",
		})
		return
	}

	receivedAttestationRequest := AttestationRequest{
		Nonce:    attestationRequest.Nonce,
		PodName:  attestationRequest.PodName,
		PodUID:   attestationRequest.PodUID,
		TenantId: attestationRequest.TenantId,
	}

	receivedAttestationRequestJSON, err := json.Marshal(receivedAttestationRequest)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error serializing Attestation Request",
			"status":  "error",
		})
		return
	}

	err = verifySignature(verifierPublicKey, string(receivedAttestationRequestJSON), attestationRequest.Signature)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Attestation Request Signature verification failed",
			"status":  "error",
		})
		return
	}

	nonceBytes, err := hex.DecodeString(attestationRequest.Nonce)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Failed to decode nonce",
			"status":  "error",
		})
		return
	}

	PCRsToQuote := []int{10}
	workerQuote, err := quoteGeneralPurposePCRs(nonceBytes, PCRsToQuote)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": err.Error(),
			"status":  "error",
		})
		return
	}

	workerIMA, err := getWorkerIMAMeasurementLog()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": err.Error(),
			"status":  "error",
		})
		return
	}

	// TODO collect claims and generate Evidence
	evidence := Evidence{
		PodName:     attestationRequest.PodName,
		PodUID:      attestationRequest.PodUID,
		TenantId:    attestationRequest.TenantId,
		WorkerQuote: workerQuote,
		WorkerIMA:   workerIMA,
	}

	evidenceDigest, err := computeEvidenceDigest(evidence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to compute Evidence digest",
			"status":  "error",
		})
		return
	}

	signedEvidence, err := signWithAIK(evidenceDigest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to sign Evidence: " + err.Error(),
			"status":  "error",
		})
		return
	}

	attestationResponse := AttestationResponse{
		Evidence:  evidence,
		Signature: signedEvidence,
	}

	c.JSON(http.StatusOK, gin.H{
		"attestationResponse": attestationResponse,
		"message":             "Attestation Request successfully processed",
		"status":              "success",
	})
	return
}

func getWorkerIMAMeasurementLog() (string, error) {
	// Open the file
	IMAMeasurementLog, err := os.Open(IMAMeasurementLogPath)
	if err != nil {
		return "", fmt.Errorf("failed to open IMA measurement logger: %v", err)
	}
	defer IMAMeasurementLog.Close()

	// Read the file content
	fileContent, err := io.ReadAll(IMAMeasurementLog)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}

	// Encode the file content into Base64
	base64Encoded := base64.StdEncoding.EncodeToString(fileContent)

	return base64Encoded, nil
}

func main() {
	initializeColors()
	loadEnvironmentVariables()
	openTPM()

	// Initialize Gin router
	r := gin.Default()

	// Define routes for the Tenant API
	r.GET("/agent/worker/registration/identify", getWorkerIdentifyingData) // GET worker identifying data (newly generated UUID, AIK, EK)
	r.POST("/agent/worker/registration/challenge", challengeWorkerEK)      // POST challenge worker for Registration
	r.POST("/agent/worker/registration/acknowledge", acknowledgeRegistration)

	r.POST("/agent/pod/attest", podAttestation) // POST attestation against one Pod running upon Worker of this agent
	// Start the server
	fmt.Printf(green.Sprintf("Agent is running on port: %s\n", agentPORT))
	err := r.Run(":" + agentPORT)
	if err != nil {
		log.Fatal("Error while starting Agent server")
	}
}
