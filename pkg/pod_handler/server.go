package pod_handler

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	clusterInteraction "github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"net/http"
	"strconv"
)

const DeployPodUrl = "/pod/deploy"
const AttestPodUrl = "/pod/attest"

type Server struct {
	podHandlerHost    string
	podHandlerPort    int
	tlsCertificate    *x509.Certificate
	registrarClient   *registrar.Client
	attestationSecret []byte
	// automatically initialized
	clusterInteractor clusterInteraction.ClusterInteraction
	router            *gin.Engine
}

func (s *Server) Init(podHandlerHost string, podHandlerPort int, tlsCertificate *x509.Certificate, registrarClient *registrar.Client, attestationSecret []byte) {
	s.podHandlerHost = podHandlerHost
	s.podHandlerPort = podHandlerPort
	s.tlsCertificate = tlsCertificate
	s.registrarClient = registrarClient
	s.attestationSecret = attestationSecret
	s.clusterInteractor.ConfigureKubernetesClient()
}

func (s *Server) SetHost(host string) {
	s.podHandlerHost = host
}

func (s *Server) SetPort(port int) {
	s.podHandlerPort = port
}

// Secure Pod Deployment Handler
func (s *Server) securePodDeployment(c *gin.Context) {
	var podDeploymentRequest model.PodDeploymentRequest
	if err := c.BindJSON(&podDeploymentRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid request format"})
		return
	}

	verifySignatureRequest := &model.VerifySignatureRequest{
		Name:      podDeploymentRequest.TenantName,
		Message:   podDeploymentRequest.Manifest,
		Signature: podDeploymentRequest.Signature,
	}

	// Verify the signature by calling the Registrar API
	signatureVerificationResponse, err := s.registrarClient.VerifyTenantSignature(verifySignatureRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Error contacting Registrar"})
		return
	}

	if signatureVerificationResponse.Status != model.Success {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "Invalid signature over provided Pod Manifest"})
	}

	if err = s.deployPod(podDeploymentRequest.Manifest, podDeploymentRequest.TenantName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": fmt.Sprintf("Failed to deploy pod: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "Pod successfully deployed"})
}

// request pod deployment
func (s *Server) deployPod(podManifest, tenantName string) error {
	tenantIdResponse, err := s.registrarClient.GetTenantIdByName(tenantName)
	if err != nil {
		return err
	}

	tenantId := tenantIdResponse.Message

	podManifestContent, err := base64.StdEncoding.DecodeString(podManifest)
	if err != nil {
		return fmt.Errorf("error decoding pod manifest: %v", err)
	}

	deployedPod, err := s.clusterInteractor.CreateTenantPodFromManifest(podManifestContent, tenantId)
	if err != nil {
		return fmt.Errorf("error creating pod: %v", err)
	}
	logger.Success("pod '%s' created successfully in namespace '%s': deployed on Worker node '%s'", deployedPod.GetObjectMeta().GetName(), deployedPod.GetNamespace(), deployedPod.Spec.NodeName)
	return nil
}

func (s *Server) requestPodAttestation(c *gin.Context) {
	var podAttestationRequest model.PodAttestationRequest
	if err := c.BindJSON(&podAttestationRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid request format"})
		return
	}

	verifySignatureRequest := &model.VerifySignatureRequest{
		Name:      podAttestationRequest.TenantName,
		Message:   podAttestationRequest.PodName,
		Signature: podAttestationRequest.Signature,
	}

	// Verify the signature by calling the Registrar API
	signatureVerificationResponse, err := s.registrarClient.VerifyTenantSignature(verifySignatureRequest)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "Error contacting Registrar"})
		return
	}

	if signatureVerificationResponse.Message != model.Success {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "Invalid Signature "})
		return
	}

	tenantIdResponse, err := s.registrarClient.GetTenantIdByName(podAttestationRequest.TenantName)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "Failed to retrieve Tenant info"})
		return
	}
	tenantId := tenantIdResponse.Message

	// get Pod information (Worker on which it is deployed, this is needed to also retrieve the Agent to contact, the Agent CRD to control ensuring Tenant ownership of pod to be attested)
	workerDeploying, agentIP, podUID, err := s.clusterInteractor.GetAttestationInformation(podAttestationRequest.PodName)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": err.Error()})
		return
	}

	agentCRDName := fmt.Sprintf("agent-%s", workerDeploying)

	// check if Pod is signed into the target Agent CRD and if it is actually owned by the calling Tenant
	_, err = s.clusterInteractor.CheckAgentCRD(agentCRDName, podAttestationRequest.PodName, tenantId)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": err.Error()})
		return
	}

	integrityMessage := fmt.Sprintf("%s::%s::%s::%s::%s", podAttestationRequest.PodName, podUID, tenantId, agentCRDName, agentIP)
	hmacValue := cryptoUtils.ComputeHMAC([]byte(integrityMessage), s.attestationSecret)

	// issue an Attestation Request for target Pod and Agent, it will be intercepted by the Verifier
	_, err = s.clusterInteractor.IssueAttestationRequestCRD(podAttestationRequest.PodName, podUID, tenantId, agentCRDName, agentIP, base64.StdEncoding.EncodeToString(hmacValue))
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"status": model.Success, "message": "Attestation Request issued with success"})
	return
}

func (s *Server) Start() {
	s.router = gin.Default()
	s.router.POST(DeployPodUrl, s.securePodDeployment)
	s.router.POST(AttestPodUrl, s.requestPodAttestation)

	logger.Info("server is running on port: %d", s.podHandlerPort)
	err := s.router.Run(":" + strconv.Itoa(s.podHandlerPort))
	if err != nil {
		logger.Fatal("failed to start pod handler: %v", err)
	}
}
