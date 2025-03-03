package main

import (
	"encoding/json"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/pod_watcher"
	"os"
)

var (
	attestationEnabledNamespaces []string
	attestationNamespaces        string
	podWatcher                   *pod_watcher.PodWatcher
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	attestationNamespaces = getEnv("ATTESTATION_NAMESPACES", "[\"default\"]")
	// setting namespaces allowed for attestation: only pods deployed  be attested
	err := json.Unmarshal([]byte(attestationNamespaces), &attestationEnabledNamespaces)
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
	podWatcher = &pod_watcher.PodWatcher{}
	podWatcher.Init(attestationEnabledNamespaces)
	podWatcher.WatchPods()
}
