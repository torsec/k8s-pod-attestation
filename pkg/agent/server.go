package agent

import (
	"crypto"
	"crypto/x509"
	"fmt"
	"github.com/gin-gonic/gin"
	"github.com/google/uuid"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/ima"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/tpm"
	"net/http"
)

type Server struct {
	agentHost         string
	agentPort         int32
	tlsCertificate    *x509.Certificate
	workerId          string
	mlPath            string
	verifierPublicKey *crypto.PublicKey
	tpm               *tpm.TPM
	router            *gin.Engine
	imaReservedPcr    uint32
	templateHashAlgo  crypto.Hash
	fileHashAlgo      crypto.Hash
	keysType          tpm.KeyType
}

const (
	GetWorkerRegistrationCredentialsUrl = "/agent/worker/registration/credentials"
	WorkerRegistrationChallengeUrl      = "/agent/worker/registration/challenge"
	AcknowledgeRegistrationUrl          = "/agent/worker/registration/acknowledge"
	PodAttestationUrl                   = "/agent/pod/attest"
)

const DefaultHashAlg = crypto.SHA256

func (s *Server) Init(agentHost string, agentPort int32, tlsCertificate *x509.Certificate, mlPath string, tpm *tpm.TPM, imaReservedPcr uint32, templateHashAlgo crypto.Hash, fileHashAlgo crypto.Hash) {
	s.agentHost = agentHost
	s.agentPort = agentPort
	s.tlsCertificate = tlsCertificate
	s.mlPath = mlPath
	s.tpm = tpm
	s.imaReservedPcr = imaReservedPcr
	s.templateHashAlgo = templateHashAlgo
	s.fileHashAlgo = fileHashAlgo
}

func (s *Server) SetHost(host string) {
	s.agentHost = host
}

func (s *Server) SetPort(port int32) {
	s.agentPort = port
}

func (s *Server) acknowledgeRegistration(c *gin.Context) {
	var acknowledge model.RegistrationAcknowledge
	var err error

	if err = c.BindJSON(&acknowledge); err != nil {
		c.JSON(http.StatusBadRequest, model.WorkerRegistrationConfirm{
			SimpleResponse: model.SimpleResponse{
				Message: "Invalid request payload",
				Status:  model.Error,
			}})
		return
	}

	if acknowledge.Status != model.Success {
		c.JSON(http.StatusOK, model.WorkerRegistrationConfirm{
			SimpleResponse: model.SimpleResponse{
				Message: "Agent acknowledged failure of registration",
				Status:  model.Error,
			}})
		return
	}

	*s.verifierPublicKey, err = cryptoUtils.DecodePublicKeyFromPEM(acknowledge.VerifierPublicKey)
	if err != nil {
		c.JSON(http.StatusBadRequest, model.WorkerRegistrationConfirm{
			SimpleResponse: model.SimpleResponse{
				Message: "Failed to decode verifier public key from PEM",
				Status:  model.Error,
			}})
		return
	}

	c.JSON(http.StatusCreated, model.WorkerRegistrationConfirm{
		SimpleResponse: model.SimpleResponse{
			Message: "Agent acknowledged success of registration and obtained Verifier Public Key",
			Status:  model.Success,
		}})
	return
}

func createAttestationEvidence(quote []byte, imaMl []byte) (*model.RatsEvidence, error) {
	evidence, err := model.NewEvidence(model.CmwCollectionTypeAttestationEvidence)
	if err != nil {
		return nil, fmt.Errorf("failed to create new evidence: %v", err)
	}

	err = evidence.AddClaim(model.IMAPcrQuoteClaimKey, quote, model.EatJsonClaimMediaType)
	if err != nil {
		return nil, fmt.Errorf("failed to create quote claim to evidence: %v", err)
	}

	err = evidence.AddClaim(model.IMAPcrQuoteClaimKey, imaMl, model.EatJsonClaimMediaType)
	if err != nil {
		return nil, fmt.Errorf("failed to add IMA measurement log claim to evidence: %v", err)
	}

	return evidence, nil
}

func createCredentialActivationEvidence(hmac, quote []byte) (*model.RatsEvidence, error) {
	evidence, err := model.NewEvidence(model.CmwCollectionTypeCredentialActivationEvidence)
	if err != nil {
		return nil, fmt.Errorf("failed to create new evidence: %v", err)
	}

	err = evidence.AddClaim(model.CredentialActivationHMACClaimKey, hmac, model.EatJsonClaimMediaType)
	if err != nil {
		return nil, fmt.Errorf("failed to add HMAC claim to evidence: %v", err)
	}
	err = evidence.AddClaim(model.IMAPcrQuoteClaimKey, quote, model.EatJsonClaimMediaType)
	if err != nil {
		return nil, fmt.Errorf("failed to add Quote claim to evidence: %v", err)
	}

	return evidence, nil
}

func (s *Server) challengeWorker(c *gin.Context) {
	var workerChallenge model.WorkerChallenge
	// Bind the JSON request body to the struct
	if err := c.BindJSON(&workerChallenge); err != nil {
		c.JSON(http.StatusBadRequest, model.WorkerChallengeResponse{
			SimpleResponse: model.SimpleResponse{
				Message: "Invalid request payload",
				Status:  model.Error,
			},
		})
		return
	}

	challengeSecret, err := s.tpm.ActivateAIKCredential(workerChallenge.AIKCredential, workerChallenge.AIKEncryptedSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.WorkerChallengeResponse{
			SimpleResponse: model.SimpleResponse{
				Message: "Agent failed to perform Credential Activation",
				Status:  model.Error,
			},
		})
		return
	}
	ephemeralKey := challengeSecret
	quoteNonce := challengeSecret[:8]

	bootQuoteJSON, err := s.tpm.QuoteBootPCRs(quoteNonce, s.templateHashAlgo, s.keysType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WorkerChallengeResponse{
			SimpleResponse: model.SimpleResponse{
				Message: "Error while computing Boot Aggregate quote",
				Status:  model.Error,
			},
		})
		return
	}

	// Compute HMAC on the worker UUID using the ephemeral key
	hmac, err := cryptoUtils.ComputeHMAC([]byte(s.workerId), ephemeralKey, DefaultHashAlg)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WorkerChallengeResponse{
			SimpleResponse: model.SimpleResponse{
				Message: "Error while computing HMAC of the worker UUID",
				Status:  model.Error,
			},
		})
		return
	}

	evidence, err := createCredentialActivationEvidence(hmac, bootQuoteJSON)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WorkerChallengeResponse{
			SimpleResponse: model.SimpleResponse{
				Message: "Failed to create credential activation evidence",
				Status:  model.Error,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.WorkerChallengeResponse{
		Evidence: evidence,
		SimpleResponse: model.SimpleResponse{
			Message: "Worker registration challenge decrypted and verified successfully",
			Status:  model.Success,
		},
	})
	return
}

func (s *Server) getWorkerRegistrationCredentials(c *gin.Context) {
	keyType, err := tpm.KeyTypeFromString(c.Param("keyType"))
	if err != nil {
		c.JSON(http.StatusBadRequest, model.WorkerChallengeResponse{
			SimpleResponse: model.SimpleResponse{
				Message: "Invalid EK key type",
				Status:  model.Error,
			},
		})
	}
	s.workerId = uuid.New().String()
	ekCert, err := s.tpm.GetWorkerEKCertificate(keyType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WorkerCredentialsResponse{
			SimpleResponse: model.SimpleResponse{
				Message: "Agent failed to fetch EK certificate",
				Status:  model.Error,
			},
		})
		return
	}

	aikNameData, aikPublicArea, err := s.tpm.CreateAIK(keyType)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WorkerCredentialsResponse{
			SimpleResponse: model.SimpleResponse{
				Message: "Agent failed to create AIK",
				Status:  model.Error,
			},
		})
		return
	}

	c.JSON(http.StatusOK, model.WorkerCredentialsResponse{
		UUID:          s.workerId,
		EKCert:        ekCert,
		AIKName:       aikNameData,
		AIKPublicArea: aikPublicArea,
		SimpleResponse: model.SimpleResponse{
			Message: "Worker registration credentials successfully generated",
			Status:  model.Success,
		},
	})
}

func (s *Server) podAttestation(c *gin.Context) {
	var attestationRequest model.AttestationRequest

	// Bind the JSON request body to the struct
	if err := c.BindJSON(&attestationRequest); err != nil {
		c.JSON(http.StatusBadRequest, model.AttestationResponse{
			SimpleResponse: model.SimpleResponse{
				Message: fmt.Sprintf("Failed to decode request: %v", err),
				Status:  model.Error,
			},
		})
		return
	}

	err := attestationRequest.VerifySignature(s.verifierPublicKey)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.AttestationResponse{
			SimpleResponse: model.SimpleResponse{
				Message: fmt.Sprintf("Failed to verify request: %v", err),
				Status:  model.Error,
			},
		})
		return
	}

	quote, err := s.tpm.QuoteGeneralPurposePCRs(attestationRequest.Nonce, []int{int(s.imaReservedPcr)}, s.templateHashAlgo, s.keysType)
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.AttestationResponse{
			SimpleResponse: model.SimpleResponse{
				Message: fmt.Sprintf("Failed to compute Quote: %v", err),
				Status:  model.Error,
			},
		})
		return
	}

	measurementList := ima.NewMeasurementListFromFile(s.mlPath, attestationRequest.Offset)
	mlContent, err := measurementList.ReadAll()
	if err != nil {
		c.JSON(http.StatusUnauthorized, model.AttestationResponse{
			SimpleResponse: model.SimpleResponse{
				Message: fmt.Sprintf("Failed to get Measurement List: %v", err),
				Status:  model.Error,
			},
		})
		return
	}

	evidence, err := createAttestationEvidence(quote, mlContent)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.AttestationResponse{
			SimpleResponse: model.SimpleResponse{
				Message: "Failed to create attestation evidence",
				Status:  model.Error,
			},
		})
		return
	}

	// TODO: Sign the evidence as JWT, agent must be provided with a pk to sign the evidence
	// for now we just return the evidence as is

	c.JSON(http.StatusOK, model.AttestationResponse{
		SimpleResponse: model.SimpleResponse{
			Message: "Pod attestation request successfully processed",
			Status:  model.Success,
		},
		Evidence:         evidence,
		ImaPcr:           s.imaReservedPcr,
		TemplateHashAlgo: s.templateHashAlgo,
		FileHashAlgo:     s.fileHashAlgo,
	})
	return
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
	logger.Info("agent is running on port: %d", s.agentPort)
	err := s.router.Run(fmt.Sprintf(":%d", s.agentPort))
	if err != nil {
		logger.Fatal("failed to start agent: %v", err)
	}
}
