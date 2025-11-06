package main

import (
	"encoding/json"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
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
	registrarHost                string
	registrarPort                int
	whitelistHost                string
	whitelistPort                int
	agentPort                    int32 = 8080
	defaultResync                int
	verifierPublicKey            string
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
	whitelistPort, err = strconv.Atoi(getEnv("WHITELIST_PORT", "8080"))
	if err != nil {
		logger.Fatal("failed to parse WHITELIST_PORT: %v", err)
	}
	verifierPublicKey = getEnv("VERIFIER_PUBLIC_KEY", "")
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
	registrarClient.Init(registrarHost, int32(registrarPort), nil)
	whitelistClient.Init(whitelistHost, int32(whitelistPort), nil)
	workerHandler.Init([]byte(verifierPublicKey), attestationEnabledNamespaces, defaultResync, &registrarClient, agentPort, &whitelistClient)
	workerHandler.WatchNodes()
}
