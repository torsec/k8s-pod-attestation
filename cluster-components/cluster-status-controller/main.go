package main

import (
	"github.com/torsec/k8s-pod-attestation/pkg/cluster_status_controller"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"os"
	"strconv"
)

var (
	clusterStatusController cluster_status_controller.ClusterStatusController
	defaultResync           int
)

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	var err error
	defaultResyncEnv := getEnv("DEFAULT_RESYNC", "3")
	defaultResync, err = strconv.Atoi(defaultResyncEnv)
	if err != nil {
		logger.Fatal("failed to parse DEFAULT_RESYNC: %v", err)
	}
}

func main() {
	loadEnvironmentVariables()
	clusterStatusController.Init(defaultResync)
	clusterStatusController.WatchAgentCRDs()
}
