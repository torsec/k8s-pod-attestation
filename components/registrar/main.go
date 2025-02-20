package main

import (
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/fatih/color"
	"github.com/gin-gonic/gin"
	"log"
	_ "modernc.org/sqlite"
	"net/http"
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

// Endpoint: Verify tenant's signature
func verifyTenantSignature(c *gin.Context) {
	var req VerifySignatureRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Get tenant public key from the database
	tenant, err := getTenantByName(req.Name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Tenant not found", "status": "error"})
		return
	}

	// Verify signature
	if err := verifySignature(tenant.PublicKey, req.Message, req.Signature); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Signature verification failed", "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Signature verification successful", "status": "success"})
}

// Endpoint: Get tenant by name (using GET method)
func getTenantIdByName(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Name parameter is required", "status": "error"})
		return
	}

	tenant, err := getTenantByName(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err, "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"tenantId": tenant.TenantID, "status": "success"})
}

// remove a Tenant from the database
func deleteTenant(workerName string) error {
	query := "DELETE FROM tenants WHERE name = ?"
	_, err := db.Exec(query, workerName)
	return err
}

// deleteTenantByName handles the deletion of a Tenant by its name
func deleteTenantByName(c *gin.Context) {
	tenantName := c.Query("name")
	if tenantName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "tenant name is required", "status": "error"})
		return
	}

	// Lock access to prevent race conditions
	mtx.Lock()
	defer mtx.Unlock()

	// Call a function to delete the worker from your data store or Kubernetes
	err := deleteTenant(tenantName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tenant deleted successfully", "status": "success"})
}

// Worker functions
// ---------------------------------------------------------------------------------------------------------------------------------

// Utility function: Check if a worker already exists by name
func workerExistsByName(name string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE name = ?"
	err := db.QueryRow(query, name).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Utility function: Check if a public key already exists
func workerExistsByAIK(AIK string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE AIK = ?"
	err := db.QueryRow(query, AIK).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Utility function: Check if a worker already exists by Id
func workerExistsById(workerId string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE workerId = ?"
	err := db.QueryRow(query, workerId).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Insert a new tenant into the database
func insertWorker(worker Worker) error {
	query := "INSERT INTO workers (workerId, name, AIK) VALUES (?, ?, ?)"
	_, err := db.Exec(query, worker.WorkerID, worker.Name, worker.AIK)
	return err
}

// Fetch the tenant by name from the database
func getWorkerByName(name string) (Worker, error) {
	var worker Worker
	query := "SELECT workerId, name, AIK FROM workers WHERE name = ?"
	err := db.QueryRow(query, name).Scan(&worker.WorkerID, &worker.Name, &worker.AIK)
	if errors.Is(err, sql.ErrNoRows) {
		return worker, errors.New("Worker not found")
	} else if err != nil {
		return worker, err
	}
	return worker, nil
}

// Endpoint: Create a new worker (with name and AIK, generating UUID for WorkerID)
func createWorker(c *gin.Context) {
	var req struct {
		WorkerId string `json:"workerId"`
		Name     string `json:"name"`
		AIK      string `json:"AIK"`
	}

	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Lock access to prevent race conditions
	mtx.Lock()
	defer mtx.Unlock()

	// Check if worker with the same name already exists
	nameExists, err := workerExistsByName(req.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check worker by name", "status": "error"})
		return
	}

	if nameExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Worker with the same name already exists", "status": "error"})
		return
	}

	// Check if worker with the same Id already exists
	idExists, err := workerExistsById(req.WorkerId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check worker by id", "status": "error"})
		return
	}

	if idExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Worker with the same UUID already exists", "status": "error"})
		return
	}

	// Check if the AIK already exists
	AIKExists, err := workerExistsByAIK(req.AIK)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check worker by AIK", "status": "error"})
		return
	}
	if AIKExists {
		c.JSON(http.StatusConflict, gin.H{"message": "AIK already exists", "status": "error"})
		return
	}

	// Create a new Worker object
	newWorker := Worker{
		WorkerID: req.WorkerId,
		Name:     req.Name,
		AIK:      req.AIK,
	}

	// Insert the new Worker into the database
	if err := insertWorker(newWorker); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create worker", "status": "error"})
		return
	}

	// Send a successful response
	c.JSON(http.StatusCreated, gin.H{
		"message":  "Worker created successfully",
		"workerId": newWorker.WorkerID,
		"status":   "success",
	})
}

// Endpoint: Verify Worker's signature using its registered AIK
func verifyWorkerSignature(c *gin.Context) {
	var req VerifySignatureRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Get tenant public key from the database
	worker, err := getWorkerByName(req.Name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Worker not found", "status": "error"})
		return
	}

	decodedMessage, err := base64.StdEncoding.DecodeString(req.Message)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Failed to decode message from base64", "status": "error"})
		return
	}

	// Verify signature
	if err := verifySignature(worker.AIK, string(decodedMessage), req.Signature); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Signature verification failed", "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Signature verification successful", "status": "success"})
	return
}

// Endpoint: Get worker by name (using GET method)
func getWorkerIdByName(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Name parameter is required", "status": "error"})
		return
	}

	worker, err := getWorkerByName(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error(), "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"workerId": worker.WorkerID, "status": "success"})
}

// remove a Worker from the database
func deleteWorker(workerName string) error {
	query := "DELETE FROM workers WHERE name = ?"
	_, err := db.Exec(query, workerName)
	return err
}

// deleteWorkerByName handles the deletion of a worker by its name
func deleteWorkerByName(c *gin.Context) {
	workerName := c.Query("name")
	if workerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "worker name is required", "status": "error"})
		return
	}

	// Lock access to prevent race conditions
	mtx.Lock()
	defer mtx.Unlock()

	// Call a function to delete the worker from your data store or Kubernetes
	err := deleteWorker(workerName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error(), "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Worker deleted successfully", "status": "success"})
}

// initializeDatabase sets up the database and creates necessary tables if they don't exist.
func initializeDatabase() error {
	var err error
	db, err = sql.Open("sqlite", "./registrar.db")
	if err != nil {
		return fmt.Errorf("failed to open registrar db: %w", err)
	}

	// Create tenants table
	createTenantTableQuery := `
	CREATE TABLE IF NOT EXISTS tenants (
		tenantId TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		publicKey TEXT NOT NULL UNIQUE
	);`
	if _, err = db.Exec(createTenantTableQuery); err != nil {
		return fmt.Errorf("failed to create tenants table: %w", err)
	}

	// Create workers table
	createWorkerTableQuery := `
	CREATE TABLE IF NOT EXISTS workers (
		workerId TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		AIK TEXT NOT NULL UNIQUE
	);`
	if _, err = db.Exec(createWorkerTableQuery); err != nil {
		return fmt.Errorf("failed to create workers table: %w", err)
	}

	// Create TPM Certificates table
	createTPMCertTableQuery := `
	CREATE TABLE IF NOT EXISTS tpm_ca_certificates (
		certificateId INTEGER PRIMARY KEY AUTOINCREMENT,
		cn TEXT NOT NULL UNIQUE,
		PEMcertificate TEXT NOT NULL UNIQUE
	);`

	if _, err = db.Exec(createTPMCertTableQuery); err != nil {
		return fmt.Errorf("failed to create TPM certificates table: %w", err)
	}

	// Create TPM Certificates table
	createTPMVendorTableQuery := `
	CREATE TABLE IF NOT EXISTS tpm_vendors (
		vendorId INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		TCGIdentifier TEXT NOT NULL UNIQUE
	);`

	if _, err = db.Exec(createTPMVendorTableQuery); err != nil {
		return fmt.Errorf("failed to create TPM vendors table: %w", err)
	}

	err = initTPMVendors()
	if err != nil {
		return fmt.Errorf("failed to insert default TPM vendors: %v", err)
	}

	err = initCACertificates()
	if err != nil {
		return fmt.Errorf("failed to insert known CA certificates: %v", err)
	}

	return nil
}

func main() {
	initializeColors()
	loadEnvironmentVariables()

	// Initialize the database
	if err := initializeDatabase(); err != nil {
		log.Fatalf("Failed to initialize database: %v", err)
	}

	defer db.Close()

	// Initialize Gin router
	r := gin.Default()

	// Define routes for the Tenant API
	r.POST("/tenant/create", createTenant)               // POST create tenant
	r.POST("/tenant/verify", verifyTenantSignature)      // POST verify tenant signature
	r.GET("/tenant/getIdByName", getTenantIdByName)      // GET tenant ID by name
	r.DELETE("/tenant/deleteByName", deleteTenantByName) // DELETE tenant by name

	r.POST("/worker/create", createWorker)                           // POST create worker
	r.POST("/worker/verify", verifyWorkerSignature)                  // POST verify worker signature
	r.POST("/worker/verifyEKCertificate", verifyWorkerEKCertificate) // POST verify worker EK certificate
	r.GET("/worker/getIdByName", getWorkerIdByName)                  // GET worker ID by name
	r.DELETE("/worker/deleteByName", deleteWorkerByName)             // DELETE worker by Name

	// Start the server
	fmt.Printf(green.Sprintf("Registrar is running on port: %s\n", registrarPORT))
	err := r.Run(":" + registrarPORT)
	if err != nil {
		log.Fatal("Error while starting Registrar server")
	}
}
