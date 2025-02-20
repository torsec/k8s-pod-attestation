package registrar

import (
	"bytes"
	"crypto/x509"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"io"
	"net/http"
	"sync"
)

type Registrar struct {
	registrarHost  string
	registrarPort  string
	tlsCertificate x509.Certificate
}

// In-memory synchronization and database reference
var (
	mtx sync.Mutex
	db  *sql.DB
)

// TPMManufacturers TCG recognized TPM manufacturers
// https://trustedcomputinggroup.org/resource/vendor-id-registry/
func getKnownTPMManufacturers() []model.TPMVendor {
	return []model.TPMVendor{
		{Name: "AMD", TCGIdentifier: "id:414D4400"},
		{Name: "Atmel", TCGIdentifier: "id:41544D4C"},
		{Name: "Broadcom", TCGIdentifier: "id:4252434D"},
		{Name: "Cisco", TCGIdentifier: "id:4353434F"},
		{Name: "Flyslice Technologies", TCGIdentifier: "id:464C5953"},
		{Name: "HPE", TCGIdentifier: "id:48504500"},
		{Name: "Huawei", TCGIdentifier: "id:48495349"},
		{Name: "IBM", TCGIdentifier: "id:49424D00"},
		{Name: "Infineon", TCGIdentifier: "id:49465800"},
		{Name: "Intel", TCGIdentifier: "id:494E5443"},
		{Name: "Lenovo", TCGIdentifier: "id:4C454E00"},
		{Name: "Microsoft", TCGIdentifier: "id:4D534654"},
		{Name: "National Semiconductor", TCGIdentifier: "id:4E534D20"},
		{Name: "Nationz", TCGIdentifier: "id:4E545A00"},
		{Name: "Nuvoton Technology", TCGIdentifier: "id:4E544300"},
		{Name: "Qualcomm", TCGIdentifier: "id:51434F4D"},
		{Name: "SMSC", TCGIdentifier: "id:534D5343"},
		{Name: "ST Microelectronics", TCGIdentifier: "id:53544D20"},
		{Name: "Samsung", TCGIdentifier: "id:534D534E"},
		{Name: "Sinosun", TCGIdentifier: "id:534E5300"},
		{Name: "Texas Instruments", TCGIdentifier: "id:54584E00"},
		{Name: "Winbond", TCGIdentifier: "id:57454300"},
		{Name: "Fuzhouk Rockchip", TCGIdentifier: "id:524F4343"},
		{Name: "Google", TCGIdentifier: "id:474F4F47"},
	}
}

func getKnownTPMCACertificates() []model.TPMCACertificate {
	return []model.TPMCACertificate{
		{CommonName: "Infineon OPTIGA(TM) RSA Manufacturing CA 003", PEMCertificate: "-----BEGIN CERTIFICATE-----\nMIIFszCCA5ugAwIBAgIEasM5FDANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJE\nRTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJP\nUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkg\nUlNBIFJvb3QgQ0EwHhcNMTQxMTI0MTUzNzE2WhcNMzQxMTI0MTUzNzE2WjCBgzEL\nMAkGA1UEBhMCREUxITAfBgNVBAoMGEluZmluZW9uIFRlY2hub2xvZ2llcyBBRzEa\nMBgGA1UECwwRT1BUSUdBKFRNKSBUUE0yLjAxNTAzBgNVBAMMLEluZmluZW9uIE9Q\nVElHQShUTSkgUlNBIE1hbnVmYWN0dXJpbmcgQ0EgMDAzMIIBIjANBgkqhkiG9w0B\nAQEFAAOCAQ8AMIIBCgKCAQEAuUD5SLLVYRmuxDjT3cWQbRTywTWUVFE3EupJQZjJ\n9mvFc2KcjpQv6rpdaT4JC33P1M9iJgrHwYO0AZlGl2FcFpSNkc/3CWoMTT9rOdwS\n/MxlNSkxwTz6IAYUYh7+pd7T49NpRRGZ1dOMfyOxWgA4C0g3EP/ciIvA2cCZ95Hf\nARD9NhuG2DAEYGNRSHY2d/Oxu+7ytzkGFFj0h1jnvGNJpWNCf3CG8aNc5gJAduMr\nWcaMHb+6fWEysg++F2FLav813+/61FqvSrUMsQg0lpE16KBA5QC2Wcr/kLZGVVGc\nuALtgJ/bnd8XgEv7W8WG+jyblUe+hkZWmxYluHS3yJeRbwIDAQABo4IBODCCATQw\nVwYIKwYBBQUHAQEESzBJMEcGCCsGAQUFBzAChjtodHRwOi8vcGtpLmluZmluZW9u\nLmNvbS9PcHRpZ2FSc2FSb290Q0EvT3B0aWdhUnNhUm9vdENBLmNydDAdBgNVHQ4E\nFgQUQLhoK40YRQorBoSdm1zZb0zd9L4wDgYDVR0PAQH/BAQDAgAGMBIGA1UdEwEB\n/wQIMAYBAf8CAQAwTAYDVR0fBEUwQzBBoD+gPYY7aHR0cDovL3BraS5pbmZpbmVv\nbi5jb20vT3B0aWdhUnNhUm9vdENBL09wdGlnYVJzYVJvb3RDQS5jcmwwFQYDVR0g\nBA4wDDAKBggqghQARAEUATAfBgNVHSMEGDAWgBTcu1ar8Rj8ppp1ERBlhBKe1UGS\nuTAQBgNVHSUECTAHBgVngQUIATANBgkqhkiG9w0BAQsFAAOCAgEAeUzrsGq3oQOT\nmF7g71TtMMndwPxgZvaB4bAc7dNettn5Yc1usikERfvJu4/iBs/Tdl6z6TokO+6V\nJuBb6PDV7f5MFfffeThraPCTeDcyYBzQRGnoCxc8Kf81ZJT04ef8CQkkfuZHW1pO\n+HHM1ZfFfNdNTay1h83x1lg1U0KnlmJ5KCVFiB94owr9t5cUoiSbAsPcpqCrWczo\nRsg1aTpokwI8Y45lqgt0SxEmQw2PIAEjHG2GQcLBDeI0c7cK5OMEjSMXStJHmNbp\nu4RHXzd+47nCD2kGV8Bx5QnK8qDVAFAe/UTDQi5mTtDFRL36Nns7jz8USemu+bw9\nl24PN73rKcB2wNF2/oFTLPHkdYfTKYGXG1g2ZkDcTAENSOq3fcTfAuyHQozBwYHG\nGGyyPHy6KvLkqMQuqeDv0QxGOtE+6cedFMP2D9bMaujR389mSm7DE6YyNQClRW7w\nJ1+rNYuN2vErvB96ir1zljXq0yMxrm5nTeiAT4p5eoFqoeSYDbFljt/f+PebREiO\nnJIy4fdvKlHAf70gPdYpYipc4oTZxLeWjDQxRFFBDFrnLdlPSg6zSL2Q3ANAEI3y\nMtHaEaU0wbaBvezyzMUHI5nLnYFL+QRP4N2OFNI/ejBaEpmIXzf6+/eF40MNLHuR\n9/B93Q+hpw8O6XZ7qx697I+5+smLlPQ=\n-----END CERTIFICATE-----"},
		{CommonName: "Infineon OPTIGA(TM) RSA Root CA", PEMCertificate: "-----BEGIN CERTIFICATE-----\nMIIFqzCCA5OgAwIBAgIBAzANBgkqhkiG9w0BAQsFADB3MQswCQYDVQQGEwJERTEh\nMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYDVQQLDBJPUFRJ\nR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElHQShUTSkgUlNB\nIFJvb3QgQ0EwHhcNMTMwNzI2MDAwMDAwWhcNNDMwNzI1MjM1OTU5WjB3MQswCQYD\nVQQGEwJERTEhMB8GA1UECgwYSW5maW5lb24gVGVjaG5vbG9naWVzIEFHMRswGQYD\nVQQLDBJPUFRJR0EoVE0pIERldmljZXMxKDAmBgNVBAMMH0luZmluZW9uIE9QVElH\nQShUTSkgUlNBIFJvb3QgQ0EwggIiMA0GCSqGSIb3DQEBAQUAA4ICDwAwggIKAoIC\nAQC7E+gc0B5T7awzux66zMMZMTtCkPqGv6a3NVx73ICg2DSwnipFwBiUl9soEodn\n25SVVN7pqmvKA2gMTR5QexuYS9PPerfRZrBY00xyFx84V+mIRPg4YqUMLtZBcAwr\nR3GO6cffHp20SBH5ITpuqKciwb0v5ueLdtZHYRPq1+jgy58IFY/vACyF/ccWZxUS\nJRNSe4ruwBgI7NMWicxiiWQmz1fE3e0mUGQ1tu4M6MpZPxTZxWzN0mMz9noj1oIT\nZUnq/drN54LHzX45l+2b14f5FkvtcXxJ7OCkI7lmWIt8s5fE4HhixEgsR2RX5hzl\n8XiHiS7uD3pQhBYSBN5IBbVWREex1IUat5eAOb9AXjnZ7ivxJKiY/BkOmrNgN8k2\n7vOS4P81ix1GnXsjyHJ6mOtWRC9UHfvJcvM3U9tuU+3dRfib03NGxSPnKteL4SP1\nbdHfiGjV3LIxzFHOfdjM2cvFJ6jXg5hwXCFSdsQm5e2BfT3dWDBSfR4h3Prpkl6d\ncAyb3nNtMK3HR5yl6QBuJybw8afHT3KRbwvOHOCR0ZVJTszclEPcM3NQdwFlhqLS\nghIflaKSPv9yHTKeg2AB5q9JSG2nwSTrjDKRab225+zJ0yylH5NwxIBLaVHDyAEu\n81af+wnm99oqgvJuDKSQGyLf6sCeuy81wQYO46yNa+xJwQIDAQABo0IwQDAdBgNV\nHQ4EFgQU3LtWq/EY/KaadREQZYQSntVBkrkwDgYDVR0PAQH/BAQDAgAGMA8GA1Ud\nEwEB/wQFMAMBAf8wDQYJKoZIhvcNAQELBQADggIBAGHTBUx3ETIXYJsaAgb2pyyN\nUltVL2bKzGMVSsnTCrXUU8hKrDQh3jNIMrS0d6dU/fGaGJvehxmmJfjaN/IFWA4M\nBdZEnpAe2fJEP8vbLa/QHVfsAVuotLD6QWAqeaC2txpxkerveoV2JAwj1jrprT4y\nrkS8SxZuKS05rYdlG30GjOKTq81amQtGf2NlNiM0lBB/SKTt0Uv5TK0jIWbz2WoZ\ngGut7mF0md1rHRauWRcoHQdxWSQTCTtgoQzeBj4IS6N3QxQBKV9LL9UWm+CMIT7Y\nnp8bSJ8oW4UdpSuYWe1ZwSjZyzDiSzpuc4gTS6aHfMmEfoVwC8HN03/HD6B1Lwo2\nDvEaqAxkya9IYWrDqkMrEErJO6cqx/vfIcfY/8JYmUJGTmvVlaODJTwYwov/2rjr\nla5gR+xrTM7dq8bZimSQTO8h6cdL6u+3c8mGriCQkNZIZEac/Gdn+KwydaOZIcnf\nRdp3SalxsSp6cWwJGE4wpYKB2ClM2QF3yNQoTGNwMlpsxnU72ihDi/RxyaRTz9OR\npubNq8Wuq7jQUs5U00ryrMCZog1cxLzyfZwwCYh6O2CmbvMoydHNy5CU3ygxaLWv\nJpgZVHN103npVMR3mLNa3QE+5MFlBlP3Mmystu8iVAKJas39VO5y5jad4dRLkwtM\n6sJa8iBpdRjZrBp5sJBI\n-----END CERTIFICATE-----\n"},
	}
}

func getTPMVendorById(vendorTCGIdentifier string) (*model.TPMVendor, error) {
	var tpmVendor *model.TPMVendor
	query := "SELECT vendorId, name, TCGIdentifier FROM tpm_vendors WHERE TCGIdentifier = ?"
	err := db.QueryRow(query, vendorTCGIdentifier).Scan(tpmVendor.VendorID, tpmVendor.Name, tpmVendor.TCGIdentifier)
	if errors.Is(err, sql.ErrNoRows) {
		return tpmVendor, fmt.Errorf("TPM Vendor not found")
	} else if err != nil {
		return tpmVendor, err
	}
	return tpmVendor, nil
}

// Fetch the Certificate by commonName from the database
func getCertificateByCommonName(commonName string) (*model.TPMCACertificate, error) {
	var tpmCert *model.TPMCACertificate
	query := "SELECT certificateId, cn, PEMCertificate FROM tpm_ca_certificates WHERE cn = ?"
	err := db.QueryRow(query, commonName).Scan(tpmCert.CertificateID, tpmCert.CommonName, tpmCert.PEMCertificate)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("certificate not found")
	} else if err != nil {
		return tpmCert, err
	}
	return tpmCert, nil
}

// Insert a new certificate into the database
func insertCertificate(tpmCertificate *model.TPMCACertificate) error {
	query := "INSERT INTO tpm_ca_certificates (cn, PEMCertificate) VALUES (?, ?, ?)"
	_, err := db.Exec(query, tpmCertificate.CommonName, tpmCertificate.PEMCertificate)
	return err
}

// Endpoint: Verify worker's TPM EK certificate
func verifyWorkerEKCertificate(c *gin.Context) {
	var req model.VerifyTPMEKCertificateRequest
	if err := c.BindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	tpmEKCertificate, err := cryptoUtils.LoadCertificateFromPEM(req.EKCertificate)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "EK Certificate is not valid PEM", "status": "error"})
		return
	}

	decodedEK, err := cryptoUtils.DecodePublicKeyFromPEM(req.EndorsementKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "EK is not valid PEM", "status": "error"})
		return
	}

	// Verify that the public key in the certificate matches the provided public key
	if !decodedEK.Equal(tpmEKCertificate.PublicKey) {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "EK does not match public key in provided EK Certificate", "status": "error"})
		return
	}

	// Get intermediate CA's certificate
	intermediateCA, err := getCertificateByCommonName(tpmEKCertificate.Issuer.CommonName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Intermediate CA not found", "status": "error"})
		return
	}

	intermediateCACert, err := cryptoUtils.LoadCertificateFromPEM(intermediateCA.PEMCertificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Intermediate CA Certificate is not valid PEM", "status": "error"})
		return
	}

	// Get intermediate CA's certificate
	rootCA, err := getCertificateByCommonName(intermediateCACert.Issuer.CommonName)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Root CA not found", "status": "error"})
		return
	}

	rootCACert, err := cryptoUtils.LoadCertificateFromPEM(rootCA.PEMCertificate)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Root CA Certificate is not valid PEM", "status": "error"})
		return
	}

	err = cryptoUtils.VerifyEKCertificateChain(tpmEKCertificate, intermediateCACert, rootCACert, getKnownTPMManufacturers())
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Certificate verification failed", "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "TPM EK Certificate verification successful", "status": "success"})
	return
}

// Tenant funcs

// Utility function: Check if a tenant already exists by name
func tenantExistsByName(name string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM tenants WHERE name = ?"
	err := db.QueryRow(query, name).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Utility function: Check if a public key already exists
func tenantExistsByPublicKey(publicKey string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM tenants WHERE publicKey = ?"
	err := db.QueryRow(query, publicKey).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Fetch the tenant by name from the database
func getTenantByName(name string) (*model.Tenant, error) {
	var tenant *model.Tenant
	query := "SELECT tenantId, name, publicKey FROM tenants WHERE name = ?"
	err := db.QueryRow(query, name).Scan(tenant.TenantID, tenant.Name, tenant.PublicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return tenant, fmt.Errorf("tenant not found")
	} else if err != nil {
		return tenant, err
	}
	return tenant, nil
}

// Insert a new tenant into the database
func insertTenant(tenant *model.Tenant) error {
	query := "INSERT INTO tenants (tenantId, name, publicKey) VALUES (?, ?, ?)"
	_, err := db.Exec(query, tenant.TenantID, tenant.Name, tenant.PublicKey)
	return err
}

// Endpoint: Create a new tenant (with name and public key, generating UUID for TenantID)
func createTenant(c *gin.Context) {
	var newTenantRequest *model.NewTenantRequest

	if err := c.BindJSON(&newTenantRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Lock access to prevent race conditions
	mtx.Lock()
	defer mtx.Unlock()

	// Check if tenant with the same name already exists
	nameExists, err := tenantExistsByName(newTenantRequest.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check tenant by name", "status": "error"})
		return
	}
	if nameExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Tenant with the same name already exists", "status": "error"})
		return
	}

	// Check if the public key already exists
	pubKeyExists, err := tenantExistsByPublicKey(newTenantRequest.PublicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check tenant by public key", "status": "error"})
		return
	}
	if pubKeyExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Public key already exists", "status": "error"})
		return
	}

	// Generate a new UUID for the tenant
	tenantID := uuid.New().String()

	// Create a new tenant object
	newTenant := model.Tenant{
		TenantID:  tenantID,
		Name:      req.Name,
		PublicKey: req.PublicKey,
	}

	// Insert the new tenant into the database
	if err := insertTenant(newTenant); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create tenant", "status": "error"})
		return
	}

	// Send a successful response
	c.JSON(http.StatusCreated, gin.H{
		"message":  "Tenant created successfully",
		"tenantId": tenantID,
		"status":   "success",
	})
}

// Exposed endpoints
func (r *Registrar) VerifyEKCertificate(EKCertcheckRequest model.VerifyTPMEKCertificateRequest) error {
	registrarCertificateValidateURL := fmt.Sprintf("http://%s:%s/worker/verifyEKCertificate", r.registrarHost, r.registrarPort)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(EKCertcheckRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal EK Certificate check request: %v", err)
	}

	// Make the POST request to the agent
	resp, err := http.Post(registrarCertificateValidateURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send EK Certificate check request: %v", err)
	}

	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Registrar failed to validate EK Certificate: %s (status: %d)", string(body), resp.StatusCode)
	}
	return nil
}

// Create a new worker in the registrar
func (r *Registrar) CreateWorker(workerNode *model.WorkerNode) (*model.NewWorkerResponse, error) {
	createWorkerURL := fmt.Sprintf("http://%s:%s/worker/create", r.registrarHost, r.registrarPort)

	jsonData, err := json.Marshal(workerNode)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal worker data: %v", err)
	}

	resp, err := http.Post(createWorkerURL, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to create worker: %v", err)
	}
	defer resp.Body.Close()

	// Read response body in case of an unexpected status
	body, _ := io.ReadAll(resp.Body)

	if resp.StatusCode != http.StatusCreated {
		return nil, fmt.Errorf("unexpected response status when creating worker: %s. Response body: %s", resp.Status, string(body))
	}
	var workerResponse model.NewWorkerResponse
	if err := json.NewDecoder(bytes.NewBuffer(body)).Decode(&workerResponse); err != nil {
		return nil, fmt.Errorf("failed to decode created worker response: %v", err)
	}
	return &workerResponse, nil
}
