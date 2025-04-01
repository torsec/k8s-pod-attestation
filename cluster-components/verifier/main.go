package main

import (
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"github.com/torsec/k8s-pod-attestation/pkg/verifier"
	"github.com/torsec/k8s-pod-attestation/pkg/whitelist"
	"os"
	"strconv"
)

var (
	attestationVerifier *verifier.Verifier
	registrarClient     *registrar.Client
	whitelistClient     *whitelist.Client
	registrarHost       string
	registrarPort       int
	whitelistHost       string
	whitelistPort       int
	attestationSecret   []byte
	verifierPrivateKey  string
	defaultResync       int
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	var err error
	registrarHost = getEnv("REGISTRAR_HOST", "localhost")
	registrarPort, err = strconv.Atoi(getEnv("REGISTRAR_PORT", "8080"))
	if err != nil {
		logger.Fatal("failed to parse REGISTRAR_PORT")
	}
	whitelistHost = getEnv("WHITELIST_HOST", "localhost")
	whitelistPort, err = strconv.Atoi(getEnv("WHITELIST_PORT", "9090"))
	if err != nil {
		logger.Fatal("failed to parse WHITELIST_PORT")
	}

	verifierPrivateKey = getEnv("VERIFIER_PRIVATE_KEY", "")
	attestationSecret = []byte(getEnv("ATTESTATION_SECRET", ""))
	defaultResyncEnv := getEnv("DEFAULT_RESYNC", "3")
	defaultResync, err = strconv.Atoi(defaultResyncEnv)
	if err != nil {
		logger.Fatal("failed to parse DEFAULT_RESYNC: %v", err)
	}
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func main() {
	loadEnvironmentVariables()
	attestationVerifier = &verifier.Verifier{}
	registrarClient = &registrar.Client{}
	registrarClient.Init(registrarHost, registrarPort, nil)
	whitelistClient = &whitelist.Client{}
	whitelistClient.Init(whitelistHost, whitelistPort, nil)

	attestationVerifier.Init(defaultResync, attestationSecret, verifierPrivateKey, registrarClient, whitelistClient)
	attestationVerifier.WatchAttestationRequestCRDs()
}
