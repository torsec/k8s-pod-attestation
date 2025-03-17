package agent

import (
	"crypto"
	"crypto/x509"
	"github.com/gin-gonic/gin"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"net/http"
	"strconv"
)

type Server struct {
	agentHost             string
	agentPort             int
	tlsCertificate        *x509.Certificate
	workerId              string
	router                *gin.Engine
	TPMPath               string
	IMAMeasurementLogPath string
	verifierPublicKey     *crypto.PublicKey
}

func (s *Server) Init(agentHost string, agentPort int, tlsCertificate *x509.Certificate) {
	s.agentHost = agentHost
	s.agentPort = agentPort
	s.tlsCertificate = tlsCertificate
}

func (s *Server) SetHost(host string) {
	s.agentHost = host
}

func (s *Server) SetPort(port int) {
	s.agentPort = port
}
func (s *Server) acknowledgeRegistration(c *gin.Context) {
	var acknowledge *model.RegistrationAcknowledge

	if err := c.BindJSON(&acknowledge); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request payload",
			"status":  "error",
		})
		return
	}

	if acknowledge.Status == model.Success {

		s.verifierPublicKey = acknowledge.VerifierPublicKey
		c.JSON(http.StatusCreated, gin.H{
			"message": "Agent acknowledged success of registration and obtained Verifier Public Key",
			"status":  "success",
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Agent acknowledged failure of registration",
		"status":  "error",
	})
}

func (s *Server) Start() {
	// Initialize Gin router
	s.router = gin.Default()

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
	logger.Info("server is running on port: %d", s.agentPort)
	err := s.router.Run(":" + strconv.Itoa(s.agentPort))
	if err != nil {
		logger.Fatal("failed to start registrar: %v", err)
	}
}
