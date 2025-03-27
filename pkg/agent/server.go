package agent

import (
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/tpm"
	"io"
	"net/http"
	"os"
	"strconv"
)

type Server struct {
	agentHost             string
	agentPort             int
	tlsCertificate        *x509.Certificate
	workerId              string
	imaMeasurementLogPath string
	verifierPublicKey     *rsa.PublicKey
	tpm                   *tpm.TPM

	router *gin.Engine
}

const (
	GetWorkerRegistrationCredentialsUrl = "/agent/worker/registration/credentials"
	WorkerRegistrationChallengeUrl      = "/agent/worker/registration/challenge"
	AcknowledgeRegistrationUrl          = "/agent/worker/registration/acknowledge"
	PodAttestationUrl                   = "/agent/pod/attest"
)

func (s *Server) Init(agentHost string, agentPort int, tlsCertificate *x509.Certificate, imaMeasurementLog string, tpm *tpm.TPM) {
	s.agentHost = agentHost
	s.agentPort = agentPort
	s.tlsCertificate = tlsCertificate
	s.imaMeasurementLogPath = imaMeasurementLog
	s.tpm = tpm
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
			"status":  model.Error,
		})
		return
	}

	if acknowledge.Status == model.Success {
		publicKey, err := base64.StdEncoding.DecodeString(acknowledge.VerifierPublicKey)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "failed to decode verifier public key from base64",
				"status":  model.Error,
			})
		}
		s.verifierPublicKey, err = cryptoUtils.DecodePublicKeyFromPEM(publicKey)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{
				"message": "failed to decode verifier public key from PEM",
				"status":  model.Error,
			})
		}

		c.JSON(http.StatusCreated, gin.H{
			"message": "Agent acknowledged success of registration and obtained Verifier Public Key",
			"status":  model.Success,
		})
		return
	}
	c.JSON(http.StatusOK, gin.H{
		"message": "Agent acknowledged failure of registration",
		"status":  model.Error,
	})
}

func (s *Server) challengeWorker(c *gin.Context) {
	var workerChallenge *model.WorkerChallenge
	// Bind the JSON request body to the struct
	if err := c.BindJSON(workerChallenge); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request payload",
			"status":  model.Error,
		})
		return
	}

	aikCredential, err := base64.StdEncoding.DecodeString(workerChallenge.AIKCredential)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "failed to decode aik credential from base64",
			"status":  model.Error,
		})
	}

	aikEncryptedSecret, err := base64.StdEncoding.DecodeString(workerChallenge.AIKEncryptedSecret)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "failed to decode aik encrypted secret from base64",
			"status":  model.Error,
		})
	}

	challengeSecret, err := s.tpm.ActivateAIKCredential(aikCredential, aikEncryptedSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Agent failed to perform Credential Activation",
			"status":  model.Error,
		})
		return
	}
	ephemeralKey := challengeSecret
	quoteNonce := challengeSecret[:8]

	bootQuoteJSON, err := s.tpm.QuoteBootPCRs(quoteNonce)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Error while computing Boot Aggregate quote",
			"status":  model.Error,
		})
		return
	}

	// Compute HMAC on the worker UUID using the ephemeral key
	challengeHmac := cryptoUtils.ComputeHMAC([]byte(s.workerId), ephemeralKey)
	encodedChallengeHmac := base64.StdEncoding.EncodeToString(challengeHmac)

	// Respond with success, including the HMAC of the UUID
	c.JSON(http.StatusOK, gin.H{
		"message":         "Worker registration challenge decrypted and verified successfully",
		"status":          model.Success,
		"HMAC":            encodedChallengeHmac,
		"workerBootQuote": bootQuoteJSON,
	})
	return
}

func (s *Server) getWorkerRegistrationCredentials(c *gin.Context) {
	s.workerId = uuid.New().String()

	ekCert, err := s.tpm.GetWorkerEKCertificate()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Agent failed to fetch EK certificate",
			"status":  model.Error,
		})
	}

	aikNameData, aikPublicArea, err := s.tpm.CreateWorkerAIK()
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Agent failed to create AIK",
			"status":  model.Error,
		})
	}

	c.JSON(http.StatusOK, gin.H{"uuid": s.workerId, "ekCert": ekCert, "aikNameData": aikNameData, "aikPublicArea": aikPublicArea})
}

func (s *Server) podAttestation(c *gin.Context) {
	var attestationRequest *model.AttestationRequest

	// Bind the JSON request body to the struct
	if err := c.BindJSON(&attestationRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Invalid request payload",
			"status":  model.Error,
		})
		return
	}

	receivedAttestationRequest := model.AttestationRequest{
		Nonce:    attestationRequest.Nonce,
		PodName:  attestationRequest.PodName,
		PodUid:   attestationRequest.PodUid,
		TenantId: attestationRequest.TenantId,
	}

	receivedAttestationRequestJSON, err := json.Marshal(receivedAttestationRequest)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error serializing Attestation Request",
			"status":  model.Error,
		})
		return
	}

	decodedAttestationRequestSignature, err := base64.StdEncoding.DecodeString(attestationRequest.Signature)
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{
			"message": "Error decoding Attestation Request Signature from base64",
			"status":  model.Error,
		})
		return
	}

	err = cryptoUtils.VerifySignature(s.verifierPublicKey, receivedAttestationRequestJSON, decodedAttestationRequestSignature)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Attestation request signature verification failed",
			"status":  model.Error,
		})
		return
	}

	nonceBytes, err := hex.DecodeString(attestationRequest.Nonce)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": "Failed to decode nonce",
			"status":  model.Error,
		})
		return
	}

	quotePcrs := []int{10}
	workerQuote, err := s.tpm.QuoteGeneralPurposePCRs(nonceBytes, quotePcrs)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": err.Error(),
			"status":  model.Error,
		})
		return
	}

	encodedQuote := base64.StdEncoding.EncodeToString(workerQuote)

	measurementLog, err := s.getWorkerMeasurementLog()
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{
			"message": err.Error(),
			"status":  model.Error,
		})
		return
	}

	// TODO standardize
	evidence := model.Evidence{
		PodName:        attestationRequest.PodName,
		PodUID:         attestationRequest.PodUid,
		TenantId:       attestationRequest.TenantId,
		Quote:          encodedQuote,
		MeasurementLog: measurementLog,
	}

	// Serialize Evidence struct to JSON
	evidenceRaw, err := json.Marshal(evidence)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to marshal Evidence",
			"status":  model.Error,
		})
		return
	}

	evidenceDigest, err := cryptoUtils.Hash(evidenceRaw)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to compute Evidence digest",
			"status":  model.Error,
		})
		return
	}

	signedEvidence, err := s.tpm.SignWithAIK(evidenceDigest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{
			"message": "Failed to sign Evidence",
			"status":  model.Error,
		})
		return
	}

	attestationResponse := &model.AttestationResponse{
		Evidence:  evidence,
		Signature: base64.StdEncoding.EncodeToString(signedEvidence),
	}

	c.JSON(http.StatusOK, gin.H{
		"attestationResponse": attestationResponse,
		"message":             "Attestation Request successfully processed",
		"status":              model.Success,
	})
	return
}

func (s *Server) getWorkerMeasurementLog() (string, error) {
	// Open the file
	imaMeasurementLog, err := os.Open(s.imaMeasurementLogPath)
	if err != nil {
		return "", fmt.Errorf("failed to open IMA measurement log: %v", err)
	}
	defer func(IMAMeasurementLog *os.File) {
		err := IMAMeasurementLog.Close()
		if err != nil {
			return
		}
	}(imaMeasurementLog)

	// Read the file content
	fileContent, err := io.ReadAll(imaMeasurementLog)
	if err != nil {
		return "", fmt.Errorf("failed to read file: %v", err)
	}
	// Encode the file content into Base64
	base64Encoded := base64.StdEncoding.EncodeToString(fileContent)
	return base64Encoded, nil
}

func (s *Server) Start() {
	// Initialize Gin router
	s.router = gin.Default()

	// Define routes for the Tenant API
	s.router.GET(GetWorkerRegistrationCredentialsUrl, s.getWorkerRegistrationCredentials) // GET worker identifying data (newly generated UUID, AIK, EK)
	s.router.POST(WorkerRegistrationChallengeUrl, s.challengeWorker)                      // POST challenge worker for Registration
	s.router.POST(AcknowledgeRegistrationUrl, s.acknowledgeRegistration)

	s.router.POST(PodAttestationUrl, s.podAttestation) // POST attestation against one Pod running upon Worker of this agent

	// Start the server
	logger.Info("server is running on port: %d", s.agentPort)
	err := s.router.Run(":" + strconv.Itoa(s.agentPort))
	if err != nil {
		logger.Fatal("failed to start registrar: %v", err)
	}
}
