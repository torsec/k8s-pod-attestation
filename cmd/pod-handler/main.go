package main

import (
	"encoding/json"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/pod_handler"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"os"
	"strconv"
)

// Global variables
var (
	podHandlerServer             pod_handler.Server
	registrarClient              registrar.Client
	podHandlerHost               string
	podHandlerPort               int
	registrarHost                string
	registrarPort                int
	attestationNamespaces        string
	attestationEnabledNamespaces []string

	//attestation secret is shared between Pod Handler and Verifier to avoid issuance of unauthentic attestation requests
	attestationSecret []byte
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	var err error
	registrarHost = getEnv("REGISTRAR_HOST", "localhost")
	registrarPort, err = strconv.Atoi(getEnv("REGISTRAR_PORT", "8080"))
	if err != nil {
		logger.Fatal("failed to parse REGISTRAR_PORT: %v", err)
	}
	podHandlerHost = getEnv("POD_HANDLER_HOST", "localhost")
	podHandlerPort, err = strconv.Atoi(getEnv("POD_HANDLER_PORT", "8081"))
	if err != nil {
		logger.Fatal("failed to parse POD_HANDLER_PORT: %v", err)
	}
	attestationNamespaces = getEnv("ATTESTATION_NAMESPACES", "[\"default\"]")
	attestationSecret = []byte(getEnv("ATTESTATION_SECRET", ""))

	// setting namespaces allowed for attestation: only pods deployed within them can be attested
	err = json.Unmarshal([]byte(attestationNamespaces), &attestationEnabledNamespaces)
	if err != nil {
		logger.Fatal("Failed to parse 'ATTESTATION_NAMESPACES' content: %v", err)
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

func main() {
	loadEnvironmentVariables()
	registrarClient.Init(registrarHost, int32(registrarPort), nil)
	podHandlerServer.Init(podHandlerHost, int32(podHandlerPort), nil, &registrarClient, attestationSecret)
	podHandlerServer.Start()
}
