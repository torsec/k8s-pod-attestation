package pod_handler

import (
	"crypto/x509"
	"encoding/base64"
	"fmt"
	"github.com/gin-gonic/gin"
	clusterInteraction "github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"net/http"
	"strconv"
)

const DeployResourceUrl = "/resource/deploy"
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

// Secure Deployment Handler
func (s *Server) secureDeployment(c *gin.Context) {
	var deploymentRequest model.DeploymentRequest
	if err := c.BindJSON(&deploymentRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid request format"})
		return
	}

	verifySignatureRequest := &model.VerifySignatureRequest{
		Name:      deploymentRequest.TenantName,
		Message:   deploymentRequest.Manifest,
		Signature: deploymentRequest.Signature,
	}

	// Verify the signature by calling the Registrar API
	signatureVerificationResponse, err := s.registrarClient.VerifyTenantSignature(verifySignatureRequest)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Error contacting Registrar"})
		return
	}

	if signatureVerificationResponse.Status != model.Success {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "Invalid signature over provided resource Manifest"})
		return
	}

	if err = s.deployResourceByKind(deploymentRequest.ResourceKind, deploymentRequest.Manifest, deploymentRequest.TenantName); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": fmt.Sprintf("Failed to deploy resource: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "Pod successfully deployed"})
}

func (s *Server) deployResourceByKind(resourceKind, manifest, tenantName string) error {
	var err error
	switch resourceKind {
	case "Pod":
		err = s.deployPod(manifest, tenantName)
		if err != nil {
			return fmt.Errorf("failed to deploy pod: %v", err)
		}
		break
	case "Deployment":
		err = s.deployDeployment(manifest, tenantName)
		if err != nil {
			return fmt.Errorf("failed to deploy deployment: %v", err)
		}
		break
	case "ReplicaSet":
		err = s.deployReplicaSet(manifest, tenantName)
		if err != nil {
			return fmt.Errorf("failed to deploy replicaSet: %v", err)
		}
		break
	case "DaemonSet":
		err = s.deployDaemonSet(manifest, tenantName)
		if err != nil {
			return fmt.Errorf("failed to deploy daemonSet: %v", err)
		}
		break
	case "StatefulSet":
		err = s.deployStatefulSet(manifest, tenantName)
		if err != nil {
			return fmt.Errorf("failed to deploy statefulSet: %v", err)
		}
		break
	default:
		return fmt.Errorf("unsupported resource kind: %s", resourceKind)
	}
	return nil
}

// request pod deployment
func (s *Server) deployPod(podManifest, tenantName string) error {
	tenantIdResponse, err := s.registrarClient.GetTenantIdByName(tenantName)
	if err != nil {
		return fmt.Errorf("error retrieving tenant ID: %v", err)
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

// request deployment of a Deployment
func (s *Server) deployDeployment(deploymentManifest, tenantName string) error {
	tenantIdResponse, err := s.registrarClient.GetTenantIdByName(tenantName)
	if err != nil {
		return err
	}

	tenantId := tenantIdResponse.Message

	deploymentManifestContent, err := base64.StdEncoding.DecodeString(deploymentManifest)
	if err != nil {
		return fmt.Errorf("error decoding deployment manifest: %v", err)
	}

	deployedDeployment, err := s.clusterInteractor.CreateTenantDeploymentFromManifest(deploymentManifestContent, tenantId)
	if err != nil {
		return fmt.Errorf("error creating deployment: %v", err)
	}
	logger.Success("deployment '%s' created successfully in namespace '%s'", deployedDeployment.GetObjectMeta().GetName(), deployedDeployment.GetNamespace())
	return nil
}

// request deployment of a ReplicaSet
func (s *Server) deployReplicaSet(replicaSetManifest, tenantName string) error {
	tenantIdResponse, err := s.registrarClient.GetTenantIdByName(tenantName)
	if err != nil {
		return err
	}

	tenantId := tenantIdResponse.Message

	replicaSetManifestContent, err := base64.StdEncoding.DecodeString(replicaSetManifest)
	if err != nil {
		return fmt.Errorf("error decoding replicaSet manifest: %v", err)
	}

	deployedReplicaSet, err := s.clusterInteractor.CreateTenantReplicaSetFromManifest(replicaSetManifestContent, tenantId)
	if err != nil {
		return fmt.Errorf("error creating replicaSet: %v", err)
	}
	logger.Success("replicaSet '%s' created successfully in namespace '%s'", deployedReplicaSet.GetObjectMeta().GetName(), deployedReplicaSet.GetNamespace())
	return nil
}

// request deployment of a DaemonSet
func (s *Server) deployDaemonSet(daemonSetManifest, tenantName string) error {
	tenantIdResponse, err := s.registrarClient.GetTenantIdByName(tenantName)
	if err != nil {
		return err
	}

	tenantId := tenantIdResponse.Message

	daemonSetManifestContent, err := base64.StdEncoding.DecodeString(daemonSetManifest)
	if err != nil {
		return fmt.Errorf("error decoding daemonSet manifest: %v", err)
	}

	deployedDaemonSet, err := s.clusterInteractor.CreateTenantDaemonSetFromManifest(daemonSetManifestContent, tenantId)
	if err != nil {
		return fmt.Errorf("error creating daemonSet: %v", err)
	}
	logger.Success("daemonSet '%s' created successfully in namespace '%s'", deployedDaemonSet.GetObjectMeta().GetName(), deployedDaemonSet.GetNamespace())
	return nil
}

// request deployment of a statefulSet
func (s *Server) deployStatefulSet(statefulSetManifest, tenantName string) error {
	tenantIdResponse, err := s.registrarClient.GetTenantIdByName(tenantName)
	if err != nil {
		return err
	}

	tenantId := tenantIdResponse.Message

	statefulSetManifestContent, err := base64.StdEncoding.DecodeString(statefulSetManifest)
	if err != nil {
		return fmt.Errorf("error decoding statefulSet manifest: %v", err)
	}

	deployedStatefulSet, err := s.clusterInteractor.CreateTenantStatefulSetFromManifest(statefulSetManifestContent, tenantId)
	if err != nil {
		return fmt.Errorf("error creating statefulSet: %v", err)
	}
	logger.Success("statefulSet '%s' created successfully in namespace '%s'", deployedStatefulSet.GetObjectMeta().GetName(), deployedStatefulSet.GetNamespace())
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
		Message:   base64.StdEncoding.EncodeToString([]byte(podAttestationRequest.PodName)),
		Signature: podAttestationRequest.Signature,
	}

	// Verify the signature by calling the Registrar API
	signatureVerificationResponse, err := s.registrarClient.VerifyTenantSignature(verifySignatureRequest)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "Error contacting Registrar"})
		return
	}

	if signatureVerificationResponse.Status != model.Success {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "Invalid Signature"})
		return
	}

	tenantIdResponse, err := s.registrarClient.GetTenantIdByName(podAttestationRequest.TenantName)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "Failed to retrieve Tenant info"})
		return
	}
	tenantId := tenantIdResponse.Message

	// get Pod information (Worker on which it is deployed, this is needed to also retrieve the Agent to contact, the Agent CRD to control ensuring Tenant ownership of pod to be attested)
	workerDeploying, agentIP, podUid, err := s.clusterInteractor.GetAttestationInformation(podAttestationRequest.PodName)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": err.Error()})
		return
	}

	// check if Pod is signed into the target Agent CRD and if it is actually owned by the calling Tenant
	_, err = s.clusterInteractor.IsPodTracked(workerDeploying, podAttestationRequest.PodName, tenantId)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": err.Error()})
		return
	}

	agentName := fmt.Sprintf("agent-%s", workerDeploying)
	// issue an Attestation Request for target Pod and Agent, it will be intercepted by the Verifier
	_, err = s.clusterInteractor.CreateAndIssueAttestationRequestCRD(podAttestationRequest.PodName, podUid, tenantId, agentName, agentIP, s.attestationSecret)
	if err != nil {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": err.Error()})
		return
	}

	c.JSON(http.StatusCreated, gin.H{"status": model.Success, "message": "Attestation Request issued with success"})
	return
}

func (s *Server) Start() {
	s.router = gin.Default()
	s.router.POST(DeployResourceUrl, s.secureDeployment)
	s.router.POST(AttestPodUrl, s.requestPodAttestation)

	logger.Info("server is running on port: %d", s.podHandlerPort)
	err := s.router.Run(":" + strconv.Itoa(s.podHandlerPort))
	if err != nil {
		logger.Fatal("failed to start pod handler: %v", err)
	}
}
