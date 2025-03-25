package main

import (
	"github.com/torsec/k8s-pod-attestation/pkg/agent"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/tpm"
	"os"
	"strconv"
)

var (
	agentServer *agent.Server
	workerTPM   *tpm.TPM
	agentHost   string
	agentPort   int
	tpmPath     string
	imaMlPath   string
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
	tpmPath = getEnv("TPM_PATH", "/dev/tpm0")
	imaMlPath = getEnv("IMA_ML_PATH", "/sys/kernel/security/integrity/ima/ascii_runtime_measurements")
	agentHost = getEnv("AGENT_HOST", "localhost")
	agentPort, err = strconv.Atoi(getEnv("AGENT_PORT", "8080"))
	if err != nil {
		logger.Fatal("failed to parse REGISTRAR_PORT: %v", err)
	}
}

func main() {
	loadEnvironmentVariables()
	agentServer = &agent.Server{}
	workerTPM = &tpm.TPM{}
	workerTPM.Init(tpmPath)
	workerTPM.OpenTPM()
	defer workerTPM.CloseTPM()

	agentServer.Init(agentHost, agentPort, nil, imaMlPath, workerTPM)
	agentServer.Start()
}
