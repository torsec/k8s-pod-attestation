package registrar

import (
	"crypto/x509"
	"database/sql"
	"encoding/base64"
	"errors"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"log"
	"net/http"
	"strconv"
	"sync"
)

type Server struct {
	registrarHost  string
	registrarPort  int
	tlsCertificate x509.Certificate
	db             *sql.DB
	mtx            sync.Mutex
	router         *gin.Engine
}

func (s *Server) SetHost(host string) {
	s.registrarHost = host
}

func (s *Server) SetPort(port int) {
	s.registrarPort = port
}

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

func (s *Server) getTPMVendorById(vendorTCGIdentifier string) (*model.TPMVendor, error) {
	var tpmVendor *model.TPMVendor
	query := "SELECT vendorId, name, TCGIdentifier FROM tpm_vendors WHERE TCGIdentifier = ?"
	err := s.db.QueryRow(query, vendorTCGIdentifier).Scan(tpmVendor.VendorID, tpmVendor.Name, tpmVendor.TCGIdentifier)
	if errors.Is(err, sql.ErrNoRows) {
		return tpmVendor, fmt.Errorf("TPM Vendor not found")
	} else if err != nil {
		return tpmVendor, err
	}
	return tpmVendor, nil
}

// Fetch the Certificate by commonName from the database
func (s *Server) getCertificateByCommonName(commonName string) (*model.TPMCACertificate, error) {
	var tpmCert *model.TPMCACertificate
	query := "SELECT certificateId, cn, PEMCertificate FROM tpm_ca_certificates WHERE cn = ?"
	err := s.db.QueryRow(query, commonName).Scan(tpmCert.CertificateID, tpmCert.CommonName, tpmCert.PEMCertificate)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, fmt.Errorf("certificate not found")
	} else if err != nil {
		return tpmCert, err
	}
	return tpmCert, nil
}

// Insert a new certificate into the database
func (s *Server) insertCertificate(tpmCertificate *model.TPMCACertificate) error {
	query := "INSERT INTO tpm_ca_certificates (cn, PEMCertificate) VALUES (?, ?, ?)"
	_, err := s.db.Exec(query, tpmCertificate.CommonName, tpmCertificate.PEMCertificate)
	return err
}

// Endpoint: Verify worker's TPM EK certificate
func (s *Server) verifyWorkerEKCertificate(c *gin.Context) {
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
	intermediateCA, err := s.getCertificateByCommonName(tpmEKCertificate.Issuer.CommonName)
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
	rootCA, err := s.getCertificateByCommonName(intermediateCACert.Issuer.CommonName)
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
func (s *Server) tenantExistsByName(name string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM tenants WHERE name = ?"
	err := s.db.QueryRow(query, name).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Utility function: Check if a public key already exists
func (s *Server) tenantExistsByPublicKey(publicKey string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM tenants WHERE publicKey = ?"
	err := s.db.QueryRow(query, publicKey).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Fetch the tenant by name from the database
func (s *Server) getTenantByName(name string) (*model.Tenant, error) {
	var tenant *model.Tenant
	query := "SELECT tenantId, name, publicKey FROM tenants WHERE name = ?"
	err := s.db.QueryRow(query, name).Scan(tenant.TenantId, tenant.Name, tenant.PublicKey)
	if errors.Is(err, sql.ErrNoRows) {
		return tenant, fmt.Errorf("tenant not found")
	} else if err != nil {
		return tenant, err
	}
	return tenant, nil
}

// Insert a new tenant into the database
func (s *Server) insertTenant(tenant *model.Tenant) error {
	query := "INSERT INTO tenants (tenantId, name, publicKey) VALUES (?, ?, ?)"
	_, err := s.db.Exec(query, tenant.TenantId, tenant.Name, tenant.PublicKey)
	return err
}

// remove a Tenant from the database
func (s *Server) deleteTenant(workerName string) error {
	query := "DELETE FROM tenants WHERE name = ?"
	_, err := s.db.Exec(query, workerName)
	return err
}

// Endpoint: deleteTenantByName handles the deletion of a Tenant by its name
func (s *Server) deleteTenantByName(c *gin.Context) {
	tenantName := c.Query("name")
	if tenantName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "tenant name is required", "status": "error"})
		return
	}

	// Lock access to prevent race conditions
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Call a function to delete the worker from your data store or Kubernetes
	err := s.deleteTenant(tenantName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": err.Error()})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Tenant deleted successfully", "status": "success"})
}

// Endpoint: Create a new tenant (with name and public key, generating UUID for TenantId)
func (s *Server) createTenant(c *gin.Context) {
	var newTenantRequest *model.NewTenantRequest

	if err := c.BindJSON(newTenantRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Lock access to prevent race conditions
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Check if tenant with the same name already exists
	nameExists, err := s.tenantExistsByName(newTenantRequest.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check tenant by name", "status": "error"})
		return
	}
	if nameExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Tenant with the same name already exists", "status": "error"})
		return
	}

	// Check if the public key already exists
	pubKeyExists, err := s.tenantExistsByPublicKey(newTenantRequest.PublicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check tenant by public key", "status": "error"})
		return
	}
	if pubKeyExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Public key already exists", "status": "error"})
		return
	}

	// Generate a new UUID for the tenant
	tenantId := uuid.New().String()

	// Create a new tenant object
	newTenant := &model.Tenant{
		TenantId:  tenantId,
		Name:      newTenantRequest.Name,
		PublicKey: newTenantRequest.PublicKey,
	}

	// Insert the new tenant into the database
	if err := s.insertTenant(newTenant); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create tenant", "status": "error"})
		return
	}

	// Send a successful response
	c.JSON(http.StatusCreated, gin.H{
		"message":  "Tenant created successfully",
		"tenantId": tenantId,
		"status":   "success",
	})
}

// Endpoint: Verify tenant's signature
func (s *Server) verifyTenantSignature(c *gin.Context) {
	var verifySignatureRequest *model.VerifySignatureRequest
	if err := c.BindJSON(verifySignatureRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Get tenant public key from the database
	tenant, err := s.getTenantByName(verifySignatureRequest.Name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Tenant not found", "status": "error"})
		return
	}

	tenantPublicKey, err := cryptoUtils.DecodePublicKeyFromPEM(tenant.PublicKey)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode public key", "status": "error"})
		return
	}

	tenantSignature, err := base64.StdEncoding.DecodeString(verifySignatureRequest.Signature)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode signature", "status": "error"})
		return
	}

	// Verify signature
	if err := cryptoUtils.VerifySignature(tenantPublicKey, []byte(verifySignatureRequest.Message), tenantSignature); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Signature verification failed", "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Signature verification successful", "status": "success"})
}

// Endpoint: Get tenant by name (using GET method)
func (s *Server) getTenantIdByName(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Name parameter is required", "status": "error"})
		return
	}

	tenant, err := s.getTenantByName(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err, "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": tenant.TenantId, "status": "success"})
}

// Worker functions
// ---------------------------------------------------------------------------------------------------------------------------------

// Utility function: Check if a worker already exists by name
func (s *Server) workerExistsByName(name string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE name = ?"
	err := s.db.QueryRow(query, name).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Utility function: Check if a public key already exists
func (s *Server) workerExistsByAIK(AIK string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE AIK = ?"
	err := s.db.QueryRow(query, AIK).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Utility function: Check if a worker already exists by Id
func (s *Server) workerExistsById(workerId string) (bool, error) {
	var count int
	query := "SELECT COUNT(*) FROM workers WHERE workerId = ?"
	err := s.db.QueryRow(query, workerId).Scan(&count)
	if err != nil {
		return false, err
	}
	return count > 0, nil
}

// Insert a new tenant into the database
func (s *Server) insertWorker(worker *model.WorkerNode) error {
	query := "INSERT INTO workers (workerId, name, AIK) VALUES (?, ?, ?)"
	_, err := s.db.Exec(query, worker.WorkerId, worker.Name, worker.AIK)
	return err
}

// Fetch the tenant by name from the database
func (s *Server) getWorkerByName(name string) (*model.WorkerNode, error) {
	var worker *model.WorkerNode
	query := "SELECT workerId, name, AIK FROM workers WHERE name = ?"
	err := s.db.QueryRow(query, name).Scan(worker.WorkerId, worker.Name, worker.AIK)
	if errors.Is(err, sql.ErrNoRows) {
		return worker, fmt.Errorf("worker not found")
	} else if err != nil {
		return worker, err
	}
	return worker, nil
}

// Endpoint: Create a new worker (with name and AIK, generating UUID for WorkerID)
func (s *Server) createWorker(c *gin.Context) {
	var newWorker *model.WorkerNode

	if err := c.BindJSON(newWorker); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Lock access to prevent race conditions
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Check if worker with the same name already exists
	nameExists, err := s.workerExistsByName(newWorker.Name)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check worker by name", "status": "error"})
		return
	}

	if nameExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Worker with the same name already exists", "status": "error"})
		return
	}

	// Check if worker with the same Id already exists
	idExists, err := s.workerExistsById(newWorker.WorkerId)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check worker by id", "status": "error"})
		return
	}

	if idExists {
		c.JSON(http.StatusConflict, gin.H{"message": "Worker with the same UUID already exists", "status": "error"})
		return
	}

	// Check if the AIK already exists
	AIKExists, err := s.workerExistsByAIK(newWorker.AIK)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to check worker by AIK", "status": "error"})
		return
	}
	if AIKExists {
		c.JSON(http.StatusConflict, gin.H{"message": "AIK already exists", "status": "error"})
		return
	}

	// Insert the new Worker into the database
	if err := s.insertWorker(newWorker); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to create worker", "status": "error"})
		return
	}

	// Send a successful response
	c.JSON(http.StatusCreated, gin.H{
		"message": newWorker.WorkerId,
		"status":  "success",
	})
}

// Endpoint: Verify Worker's signature using its registered AIK
func (s *Server) verifyWorkerSignature(c *gin.Context) {
	var verifySignatureRequest *model.VerifySignatureRequest
	if err := c.BindJSON(verifySignatureRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Invalid request payload", "status": "error"})
		return
	}

	// Get tenant public key from the database
	worker, err := s.getWorkerByName(verifySignatureRequest.Name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": "Worker not found", "status": "error"})
		return
	}

	decodedMessage, err := base64.StdEncoding.DecodeString(verifySignatureRequest.Message)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Failed to decode message from base64", "status": "error"})
		return
	}

	workerPublicKey, err := cryptoUtils.DecodePublicKeyFromPEM(worker.AIK)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode public key", "status": "error"})
		return
	}

	workerSignature, err := base64.StdEncoding.DecodeString(verifySignatureRequest.Signature)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": "Failed to decode signature", "status": "error"})
		return
	}

	// Verify signature
	if err := cryptoUtils.VerifySignature(workerPublicKey, decodedMessage, workerSignature); err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"message": "Signature verification failed", "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Signature verification successful", "status": "success"})
	return
}

// Endpoint: Get worker by name (using GET method)
func (s *Server) getWorkerIdByName(c *gin.Context) {
	name := c.Query("name")
	if name == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "Name parameter is required", "status": "error"})
		return
	}

	worker, err := s.getWorkerByName(name)
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"message": err.Error(), "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": worker.WorkerId, "status": "success"})
}

// remove a Worker from the database
func (s *Server) deleteWorker(workerName string) error {
	query := "DELETE FROM workers WHERE name = ?"
	_, err := s.db.Exec(query, workerName)
	return err
}

// deleteWorkerByName handles the deletion of a worker by its name
func (s *Server) deleteWorkerByName(c *gin.Context) {
	workerName := c.Query("name")
	if workerName == "" {
		c.JSON(http.StatusBadRequest, gin.H{"message": "worker name is required", "status": "error"})
		return
	}

	// Lock access to prevent race conditions
	s.mtx.Lock()
	defer s.mtx.Unlock()

	// Call a function to delete the worker from your data store or Kubernetes
	err := s.deleteWorker(workerName)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"message": err.Error(), "status": "error"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Worker deleted successfully", "status": "success"})
}

// Tenant functions
// ---------------------------------------------------------------------------------------------------------------------------

func (s *Server) initCACertificates() error {
	// Prepare the insert statement
	insertCertificateQuery := `INSERT INTO tpm_ca_certificates (cn, PEMCertificate) VALUES (?, ?);`
	query, err := s.db.Prepare(insertCertificateQuery)
	if err != nil {
		return fmt.Errorf("error preparing statement: %v", err)
	}

	defer func(query *sql.Stmt) {
		err := query.Close()
		if err != nil {
			return
		}
	}(query)

	// Insert vendors into the database
	for _, caCertificate := range getKnownTPMCACertificates() {
		_, err := query.Exec(caCertificate.CommonName, caCertificate.PEMCertificate)
		if err != nil {
			return fmt.Errorf("error inserting TPM vendor %s: %v", caCertificate.CommonName, err)
		}
	}
	return nil
}

func (s *Server) initTPMVendors() error {
	// Prepare the insert statement
	insertVendorQuery := `INSERT INTO tpm_vendors (name, TCGIdentifier) VALUES (?, ?);`
	query, err := s.db.Prepare(insertVendorQuery)
	if err != nil {
		return fmt.Errorf("error preparing statement: %v", err)
	}

	defer func(query *sql.Stmt) {
		err := query.Close()
		if err != nil {
			return
		}
	}(query)

	// Insert vendors into the database
	for _, vendor := range getKnownTPMManufacturers() {
		_, err := query.Exec(vendor.Name, vendor.TCGIdentifier)
		if err != nil {
			return fmt.Errorf("error inserting TPM vendor %s: %v", vendor.Name, err)
		}
	}
	return nil
}

func (s *Server) Start() {
	// Initialize Gin router
	s.router = gin.Default()
	defer s.db.Close()

	// Define routes for the Tenant API
	s.router.POST("/tenant/create", s.createTenant)               // POST create tenant
	s.router.POST("/tenant/verify", s.verifyTenantSignature)      // POST verify tenant signature
	s.router.GET("/tenant/getIdByName", s.getTenantIdByName)      // GET tenant ID by name
	s.router.DELETE("/tenant/deleteByName", s.deleteTenantByName) // DELETE tenant by name

	s.router.POST("/worker/create", s.createWorker)                           // POST create worker
	s.router.POST("/worker/verify", s.verifyWorkerSignature)                  // POST verify worker signature
	s.router.POST("/worker/verifyEKCertificate", s.verifyWorkerEKCertificate) // POST verify worker EK certificate
	s.router.GET("/worker/getIdByName", s.getWorkerIdByName)                  // GET worker ID by name
	s.router.DELETE("/worker/deleteByName", s.deleteWorkerByName)             // DELETE worker by Name

	// Start the server
	fmt.Println("Server is running on port: %i", s.registrarPort)
	err := s.router.Run(":" + strconv.Itoa(s.registrarPort))
	if err != nil {
		log.Fatal("Error while starting Server server")
	}
}

// InitializeRegistrarDatabase sets up the database and creates necessary tables if they don't exist.
func (s *Server) InitializeRegistrarDatabase() error {
	var err error
	s.db, err = sql.Open("sqlite", "./registrar.db")
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
	if _, err = s.db.Exec(createTenantTableQuery); err != nil {
		return fmt.Errorf("failed to create tenants table: %w", err)
	}

	// Create workers table
	createWorkerTableQuery := `
	CREATE TABLE IF NOT EXISTS workers (
		workerId TEXT PRIMARY KEY,
		name TEXT NOT NULL UNIQUE,
		AIK TEXT NOT NULL UNIQUE
	);`
	if _, err = s.db.Exec(createWorkerTableQuery); err != nil {
		return fmt.Errorf("failed to create workers table: %w", err)
	}

	// Create TPM Certificates table
	createTPMCertTableQuery := `
	CREATE TABLE IF NOT EXISTS tpm_ca_certificates (
		certificateId INTEGER PRIMARY KEY AUTOINCREMENT,
		cn TEXT NOT NULL UNIQUE,
		PEMcertificate TEXT NOT NULL UNIQUE
	);`

	if _, err = s.db.Exec(createTPMCertTableQuery); err != nil {
		return fmt.Errorf("failed to create TPM certificates table: %w", err)
	}

	// Create TPM Certificates table
	createTPMVendorTableQuery := `
	CREATE TABLE IF NOT EXISTS tpm_vendors (
		vendorId INTEGER PRIMARY KEY AUTOINCREMENT,
		name TEXT NOT NULL UNIQUE,
		TCGIdentifier TEXT NOT NULL UNIQUE
	);`

	if _, err = s.db.Exec(createTPMVendorTableQuery); err != nil {
		return fmt.Errorf("failed to create TPM vendors table: %w", err)
	}

	err = s.initTPMVendors()
	if err != nil {
		return fmt.Errorf("failed to insert default TPM vendors: %v", err)
	}

	err = s.initCACertificates()
	if err != nil {
		return fmt.Errorf("failed to insert known CA certificates: %v", err)
	}

	return nil
}
