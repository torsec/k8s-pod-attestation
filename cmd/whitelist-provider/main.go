package main

import (
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/whitelist"
	"os"
	"strconv"
)

// MongoDB client and global variables
var (
	whitelistServer whitelist.Server
	whitelistHost   string
	whitelistPort   int
	whitelistUri    string
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	var err error
	whitelistHost = getEnv("WHITELIST_HOST", "localhost")
	whitelistPort, err = strconv.Atoi(getEnv("WHITELIST_PORT", "9090"))
	if err != nil {
		logger.Fatal("failed to get WHITELIST_PORT")
	}
	whitelistUri = getEnv("WHITELIST_DB_URI", "mongodb://localhost:27017")
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
	whitelistServer.Init(whitelistHost, whitelistPort, whitelistUri, nil)
	whitelistServer.Start()
}
