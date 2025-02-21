package main

import (
	"database/sql"
	"github.com/fatih/color"
	"log"
	_ "modernc.org/sqlite"
	"os"
	"sync"
)

// Tenant struct represents a tenant in the system

// VerifySignatureRequest represents the input data for signature verification
type VerifySignatureRequest struct {
	Name      string `json:"name"`
	Message   string `json:"message"`
	Signature string `json:"signature"`
}

type TPMCACertificate struct {
	CertificateID  string `json:"certificateId,omitempty"`
	CommonName     string `json:"commonName"`
	PEMCertificate string `json:"PEMCertificate"`
}

type VerifyTPMEKCertificateRequest struct {
	EndorsementKey string `json:"endorsementKey"`
	EKCertificate  string `json:"EKCertificate"`
}

type TPMVendor struct {
	VendorID      string `json:"vendorId,omitempty"`
	Name          string `json:"vendorName"`
	TCGIdentifier string `json:"TCGIdentifier"`
}

// In-memory synchronization and database reference
var (
	mtx sync.Mutex
	db  *sql.DB
)

var (
	red           *color.Color
	green         *color.Color
	yellow        *color.Color
	registrarPORT string
)

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

// initializeColors sets up color variables for console output.
func initializeColors() {
	red = color.New(color.FgRed)
	green = color.New(color.FgGreen)
	yellow = color.New(color.FgYellow)
}

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	registrarPORT = getEnv("REGISTRAR_PORT", "8080")
}

// Tenant functions
// ---------------------------------------------------------------------------------------------------------------------------

func main() {
	initializeColors()
	loadEnvironmentVariables()

	// Initialize the database
	if err := initializeDatabase(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	defer db.Close()

}
