package main

import (
	"encoding/json"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/pod_watcher"
	"os"
	"strconv"
)

var (
	attestationEnabledNamespaces []string
	attestationNamespaces        string
	defaultResync                int
	podWatcher                   pod_watcher.PodWatcher
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	var err error
	attestationNamespaces = getEnv("ATTESTATION_NAMESPACES", "[\"default\"]")
	defaultResyncEnv := getEnv("DEFAULT_RESYNC", "3")

	defaultResync, err = strconv.Atoi(defaultResyncEnv)
	if err != nil {
		logger.Fatal("failed to parse DEFAULT_RESYNC: %v", err)
	}
	// setting namespaces allowed for attestation: only pods deployed be attested
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
	podWatcher.Init(attestationEnabledNamespaces, defaultResync)
	podWatcher.WatchPods()
}
