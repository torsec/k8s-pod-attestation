package main

import (
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"os"
	"strconv"
)

var (
	registrarServer *registrar.Server
	registrarHost   string
	registrarPort   int
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
	registrarHost = getEnv("REGISTRAR_HOST", "localhost")
	registrarPort, err = strconv.Atoi(getEnv("REGISTRAR_PORT", "8080"))
	if err != nil {
		logger.Fatal("failed to parse REGISTRAR_PORT: %v", err)
	}
}

func main() {
	loadEnvironmentVariables()
	registrarServer = &registrar.Server{}
	registrarServer.Init(registrarHost, registrarPort, nil)
	err := registrarServer.InitializeRegistrarDatabase()
	if err != nil {
		logger.Fatal("Failed to initialize registrar database: %s", err)
	}
	registrarServer.Start()
}
