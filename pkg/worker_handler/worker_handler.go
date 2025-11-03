package worker_handler

import (
	"context"
	"crypto"
	"crypto/ecdsa"
	"crypto/rsa"
	"encoding/hex"
	"encoding/json"
	"github.com/google/go-tpm-tools/client"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/torsec/k8s-pod-attestation/pkg/agent"
	"github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"github.com/torsec/k8s-pod-attestation/pkg/tpm"
	"github.com/torsec/k8s-pod-attestation/pkg/tpm_attestation"
	"github.com/torsec/k8s-pod-attestation/pkg/whitelist"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const ephemeralKeySize = 16
const defaultHashAlgorithm = crypto.SHA256
const defaultTPMKeyType = tpm.RSA

type WorkerHandler struct {
	clusterInteractor cluster_interaction.ClusterInteraction
	informerFactory   informers.SharedInformerFactory
	registrarClient   *registrar.Client
	agentConfig       *model.AgentConfig
	agentClient       *agent.Client
	whitelistClient   *whitelist.Client
	verifierPublicKey []byte
}

func (wh *WorkerHandler) Init(verifierPublicKey []byte, attestationEnabledNamespaces []string, defaultResync int, registrarClient *registrar.Client, agentConfig *model.AgentConfig, whitelistClient *whitelist.Client) {
	wh.verifierPublicKey = verifierPublicKey
	wh.clusterInteractor.ConfigureKubernetesClient()
	wh.clusterInteractor.AttestationEnabledNamespaces = attestationEnabledNamespaces
	wh.informerFactory = informers.NewSharedInformerFactory(wh.clusterInteractor.ClientSet, time.Minute*time.Duration(defaultResync))
	err := wh.clusterInteractor.DefineAgentCRD()
	if err != nil {
		logger.Error("Failed to initialize Worker Handler: %v", err)
	}
	wh.registrarClient = registrarClient
	wh.agentConfig = agentConfig
	wh.whitelistClient = whitelistClient
}

func (wh *WorkerHandler) SetAgentClient(agentClient *agent.Client) {
	wh.agentClient = agentClient
}

func (wh *WorkerHandler) deleteNodeHandling(obj interface{}) {
	node := obj.(*corev1.Node)

	isControlPlane, err := wh.clusterInteractor.NodeIsControlPlane("", node)
	if err != nil {
		logger.Error("Failed to determine if node '%s' is control-plane: %v", node.GetName(), err)
		return
	}

	if isControlPlane {
		logger.Info("node '%s' is control-plane; skipping registration", node.GetName())
		return
	}

	logger.Info("Worker node '%s' removed from the cluster; removing Agent and Agent CRD", node.GetName())

	registrarResponse, err := wh.registrarClient.RemoveWorker(node.GetName())
	if err != nil {
		logger.Error("Failed to remove contact Registrar to remove worker '%s': %v", node.GetName(), err)
		return
	}

	if registrarResponse.Status != model.Success {
		logger.Error("Failed to remove worker '%s' from Registrar: %s", node.GetName(), registrarResponse.Message)
	}

	err = wh.clusterInteractor.DeleteAgent(node.GetName())
	if err != nil {
		logger.Error("Failed to delete Agent from worker '%s': %v", node.GetName(), err)
		return
	}
	err = wh.clusterInteractor.DeleteAgentCRDInstance(node.GetName())
	if err != nil {
		logger.Error("Failed to delete Agent CRD of worker '%s': %v", node.GetName(), err)
		return
	}
	logger.Success("Successfully deleted Agent and Agent CRD of worker '%s'", node.GetName())
}

func (wh *WorkerHandler) addNodeHandling(obj interface{}) {
	node := obj.(*corev1.Node)

	isControlPlane, err := wh.clusterInteractor.NodeIsControlPlane("", node)
	if err != nil {
		logger.Error("Failed to determine if node '%s' is control-plane: %v", node.GetName(), err)
		_, err = wh.clusterInteractor.DeleteNode(node.GetName())
		if err != nil {
			logger.Fatal("Failed to delete node '%s': %v", node.GetName(), err)
		}
		return
	}

	if isControlPlane {
		logger.Info("node '%s' is control-plane; skipping registration", node.GetName())
		return
	}

	workerResponse, err := wh.registrarClient.GetWorkerIdByName(node.GetName())
	if err != nil {
		logger.Error("Failed to determine if node '%s' is registered: %v", node.GetName(), err)
		_, err = wh.clusterInteractor.DeleteNode(node.GetName())
		if err != nil {
			logger.Fatal("Failed to delete node '%s': %v", node.GetName(), err)
		}
		return
	}

	if workerResponse.Status == model.Success {
		logger.Info("node '%s' already registered; skipping registration", node.GetName())
		return
	}

	logger.Info("new worker node '%s' joined the cluster: starting registration", node.GetName())

	_, agentDeploymentName, agentHost, agentPort, err := wh.clusterInteractor.DeployAgent(node, wh.agentConfig)
	if err != nil {
		logger.Error("Failed to start Agent on node '%s': %v; deleting node from cluster", node.GetName(), err)
		_, err := wh.clusterInteractor.DeleteNode(node.GetName())
		if err != nil {
			logger.Fatal("Failed to delete node '%s': %v", node.GetName(), err)
		}
		return
	}

	wh.agentClient = &agent.Client{}
	wh.agentClient.Init(agentHost, int32(agentPort), nil)

	logger.Info("successfully deployed agent on node '%s'; service port: %d", node.GetName(), agentPort)

	isNewWorkerRegistered := wh.workerRegistration(node, agentDeploymentName)

	if !isNewWorkerRegistered {
		logger.Error("Failed to register node '%s'; deleting node from cluster", node.GetName())
		_, err := wh.clusterInteractor.DeleteNode(node.GetName())
		if err != nil {
			logger.Fatal("Failed to delete node '%s': %v", node.GetName(), err)
		}
	}

	isAgentCreated, err := wh.clusterInteractor.CreateAgentCRDInstance(node.GetName())
	if err != nil || !isAgentCreated {
		logger.Error("Failed to create agent CRD instance on node '%s': %v; deleting node from cluster", node.GetName(), err)
		_, err := wh.clusterInteractor.DeleteNode(node.GetName())
		if err != nil {
			logger.Fatal("Failed to delete node '%s': %v", node.GetName(), err)
		}
	}
}

// workerRegistration registers the worker node by calling the identification API
func (wh *WorkerHandler) workerRegistration(newWorker *corev1.Node, agentDeploymentName string) bool {
	err := wh.clusterInteractor.WaitForAllDeploymentPodsRunning(cluster_interaction.PodAttestationNamespace, agentDeploymentName, 1*time.Minute)
	if err != nil {
		logger.Error("Agent deployment not ready to run: %v", err)
		return false
	}

	err = wh.agentClient.WaitForAgent(1*time.Second, 1*time.Minute)
	if err != nil {
		logger.Error("Error while contacting Agent: %v", err.Error())
		return false
	}
	// Call Agent to identify worker data
	workerCredentials, err := wh.agentClient.WorkerRegistrationCredentials(defaultTPMKeyType.String())
	if err != nil {
		logger.Error("Failed to start get worker credentials and identification data: %v", err)
		return false
	}

	// TEST: this allows the agent in 'simulator' mode to be compliant with the framework
	ekCertCheckRequest := model.VerifyTPMEKCertificateRequest{
		EKCertificate: workerCredentials.EKCert,
	}

	ekVerificationResponse, err := wh.registrarClient.VerifyEKCertificate(ekCertCheckRequest)
	if err != nil {
		logger.Error("Failed to verify EK Certificate: %v", err)
		return false
	}

	if ekVerificationResponse.Status != model.Success {
		logger.Error("Invalid EK Certificate: %s", ekVerificationResponse.Message)
		return false
	}

	ekCert, err := cryptoUtils.LoadCertificateFromPEM(workerCredentials.EKCert)
	if err != nil {
		logger.Error("Failed to load EK Certificate: %v", err)
		return false
	}

	ek := ekCert.PublicKey
	var template tpm2.Public
	switch ek.(type) {
	case *rsa.PublicKey:
		template = client.AKTemplateRSA()
		break
	case *ecdsa.PublicKey:
		template = client.AKTemplateECC()
		break
	default:
		logger.Error("Unsupported Key type")
		return false
	}

	aikPublicKey, err := tpm_attestation.ValidateAIKPublicData(workerCredentials.AIKName, workerCredentials.AIKPublicArea, template)
	if err != nil {
		logger.Error("Failed to validate received Worker AIK: %v", err)
		return false
	}

	// Generate ephemeral key
	ephemeralKey, err := cryptoUtils.GenerateEphemeralKey(ephemeralKeySize)
	if err != nil {
		logger.Error("Failed to generate challenge ephemeral key: %v", err)
		return false
	}

	// Some TPMs cannot process secrets > 32 bytes, so first 8 bytes of the ephemeral key are used as nonce of quote computation
	quoteNonce := ephemeralKey[:8]
	// TODO kdf instead of raw ephemeral key piece

	encodedCredentialBlob, encodedEncryptedSecret, err := tpm_attestation.GenerateCredentialActivation(workerCredentials.AIKName, ek, ephemeralKey)
	if err != nil {
		logger.Error("Failed to generate AIK credential activation challenge: %v", err)
		return false
	}

	// Prepare challenge payload for sending
	workerChallenge := &model.WorkerChallenge{
		AIKCredential:      encodedCredentialBlob,
		AIKEncryptedSecret: encodedEncryptedSecret,
	}

	// Send challenge request to the agent
	challengeResponse, err := wh.agentClient.WorkerRegistrationChallenge(workerChallenge)
	if err != nil {
		logger.Error("Failed to send challenge request: %v", err)
		return false
	}

	hmac, err := challengeResponse.Evidence.GetClaim(model.CredentialActivationHMACClaimKey)
	if err != nil {
		logger.Error("Failed to get hmac value: %v", err)
		return false
	}

	// Verify the HMAC response from the agent
	err = cryptoUtils.VerifyHMAC([]byte(workerCredentials.UUID), ephemeralKey, hmac, defaultHashAlgorithm)
	if err != nil {
		logger.Error("Failed to verify HMAC: %v", err)
		return false
	}

	quoteJSON, err := challengeResponse.Evidence.GetClaim(model.IMAPcrQuoteClaimKey)
	if err != nil {
		logger.Error("Failed to get quote: %v", err)
		return false
	}

	// Parse inputQuote JSON
	var quote *pb.Quote
	err = json.Unmarshal(quoteJSON, &quote)
	if err != nil {
		logger.Error("Failed to unmarshal quote for validation: %v", err)
		return false
	}

	err = tpm_attestation.ValidateQuoteStructure(quote, quoteNonce)
	if err != nil {
		logger.Error("Failed to validate Worker Quote: %v", err)
		return false
	}

	bootAggregate, err := tpm_attestation.GetPCRDigest(quote)
	if err != nil {
		logger.Error("Failed to get boot aggregate: %v", err)
		return false
	}

	workerWhitelistCheckRequest := &model.WorkerWhitelistCheckRequest{
		OsName:        newWorker.Status.NodeInfo.OSImage,
		BootAggregate: hex.EncodeToString(bootAggregate),
		HashAlg:       challengeResponse.HashAlgo,
	}

	whitelistResponse, err := wh.whitelistClient.CheckWorkerWhitelist(workerWhitelistCheckRequest)
	if err != nil {
		logger.Error("Worker Boot validation failed: %v", err)
		return false
	}

	if whitelistResponse.Status != model.Success {
		logger.Error("Untrusted Boot measurements for Worker node '%s'; %s;", newWorker.GetName(), whitelistResponse.ErroredEntries.ToString())
		return false
	}

	attestedDependencies, err := json.Marshal(workerWhitelistCheckRequest)
	if err != nil {
		logger.Error("Failed to marshal attested entries as json")
	}

	logger.Success("Attestation of Worker node '%s' completed with success; Successfully attested dependencies: %s", newWorker.GetName(), attestedDependencies)

	aikPublicPem, err := cryptoUtils.EncodePublicKeyToPEM(aikPublicKey)
	if err != nil {
		logger.Error("Failed to encode AIK public key: %v", err)
		return false
	}
	if aikPublicPem == nil {
		logger.Error("Failed to parse AIK Public Key to PEM format")
		return false
	}

	workerNode := &model.WorkerNode{
		WorkerId: workerCredentials.UUID,
		Name:     newWorker.GetName(),
		AIK:      aikPublicPem,
	}

	// Create a new worker
	createWorkerResponse, err := wh.registrarClient.CreateWorker(workerNode)
	if err != nil {
		logger.Error("Failed to create Worker Node: %v", err)
	}

	registrationAcknowledge := &model.RegistrationAcknowledge{
		SimpleResponse: model.SimpleResponse{
			Message: createWorkerResponse.Message,
			Status:  createWorkerResponse.Status,
		},
	}

	if createWorkerResponse.Status == model.Success {
		registrationAcknowledge.VerifierPublicKey = wh.verifierPublicKey
	}

	registrationConfirm, err := wh.agentClient.WorkerRegistrationAcknowledge(registrationAcknowledge)
	if err != nil {
		logger.Error("Failed to acknowledge Worker Node about registration result: %v", err)
		return false
	}

	if registrationConfirm.Status != model.Success {
		logger.Error("Worker Node registration confirmation failed: %s", registrationConfirm.Message)
		return false
	}

	logger.Success("Successfully registered Worker Node '%s': %s", newWorker.GetName(), workerCredentials.UUID)
	return true
}

func (wh *WorkerHandler) WatchNodes() {
	ctx := setupSignalHandler()
	nodeInformer := wh.informerFactory.Core().V1().Nodes().Informer()

	nodeEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    wh.addNodeHandling,
		UpdateFunc: func(old, new interface{}) {},
		DeleteFunc: wh.deleteNodeHandling,
	}

	// Add event handlers for Node events
	_, err := nodeInformer.AddEventHandler(nodeEventHandler)
	if err != nil {
		logger.Fatal("failed to create node event handler: %v", err)
	}

	// Start the informer
	go nodeInformer.Run(ctx.Done())

	// Wait for the informer to sync
	if !cache.WaitForCacheSync(ctx.Done(), nodeInformer.HasSynced) {
		logger.Warning("Timed out waiting for caches to sync")
		return
	}

	// Keep running until stopped
	<-ctx.Done()
	logger.Info("stopping Worker Handler...")
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() context.Context {
	ctx, cancel := context.WithCancel(context.Background())
	c := make(chan os.Signal, 2)
	signal.Notify(c, syscall.SIGINT, syscall.SIGTERM)

	go func() {
		<-c
		cancel()
	}()
	return ctx
}
