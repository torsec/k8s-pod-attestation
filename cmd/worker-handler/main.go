package main

import (
	"encoding/json"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"github.com/torsec/k8s-pod-attestation/pkg/whitelist"
	"github.com/torsec/k8s-pod-attestation/pkg/worker_handler"
	"log"
	"os"
	"strconv"
)

// Color variables for output
var (
	attestationNamespaces        string
	attestationEnabledNamespaces []string
	agentImageName               string
	registrarHost                string
	registrarPort                int
	whitelistHost                string
	whitelistPort                int
	agentPort                    int32 = 9090
	agentNodePortAllocation      int32 = 31000
	imaMountPath                 string
	imaMlPath                    string
	tpmPath                      string
	defaultResync                int
	verifierPublicKey            string
	agentConfig                  model.AgentConfig
	workerHandler                worker_handler.WorkerHandler
	registrarClient              registrar.Client
	whitelistClient              whitelist.Client
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	var err error
	registrarHost = getEnv("REGISTRAR_HOST", "localHost")
	registrarPort, err = strconv.Atoi(getEnv("REGISTRAR_PORT", "8080"))
	if err != nil {
		logger.Fatal("failed to parse REGISTRAR_PORT: %v", err)
	}
	attestationNamespaces = getEnv("ATTESTATION_NAMESPACES", "[\"default\"]")
	whitelistHost = getEnv("WHITELIST_HOST", "localHost")
	whitelistPort, err = strconv.Atoi(getEnv("WHITELIST_PORT", "9090"))
	if err != nil {
		logger.Fatal("failed to parse WHITELIST_PORT: %v", err)
	}
	verifierPublicKey = getEnv("VERIFIER_PUBLIC_KEY", "")
	imaMountPath = getEnv("IMA_MOUNT_PATH", "/root/ascii_runtime_measurements")
	imaMlPath = getEnv("IMA_ML_PATH", "/sys/kernel/security/integrity/ima/ascii_runtime_measurements")
	tpmPath = getEnv("TPM_PATH", "/dev/tpm0")
	agentImageName = getEnv("AGENT_IMAGE_NAME", "franczar/k8s-attestation-agent:latest")
	defaultResyncEnv := getEnv("DEFAULT_RESYNC", "3")
	defaultResync, err = strconv.Atoi(defaultResyncEnv)
	if err != nil {
		logger.Fatal("failed to parse DEFAULT_RESYNC: %v", err)
	}

	// setting namespaces allowed for attestation: only pods deployed within them can be attested
	err = json.Unmarshal([]byte(attestationNamespaces), &attestationEnabledNamespaces)
	if err != nil {
		log.Fatalf("Failed to parse 'ATTESTATION_NAMESPACES' content: %v", err)
	}
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		if key == "ATTESTATION_NAMESPACES" {
			logger.Warning("'%s' environment variable missing: setting default value: ['default']", key)
		}
		return defaultValue
	}
	return value
}

// Main function
func main() {
	loadEnvironmentVariables()

	agentConfig = model.AgentConfig{
		TPMPath:                 tpmPath,
		IMAMountPath:            imaMountPath,
		IMAMeasurementLogPath:   imaMlPath,
		ImageName:               agentImageName,
		AgentPort:               agentPort,
		AgentNodePortAllocation: agentNodePortAllocation,
	}

	registrarClient.Init(registrarHost, registrarPort, nil)
	whitelistClient.Init(whitelistHost, whitelistPort, nil)
	workerHandler.Init(verifierPublicKey, attestationEnabledNamespaces, defaultResync, &registrarClient, &agentConfig, &whitelistClient)
	workerHandler.WatchNodes()
}
