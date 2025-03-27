package worker_handler

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/agent"
	"github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"github.com/torsec/k8s-pod-attestation/pkg/tpm_attestation"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const ephemeralKeySize = 16

type WorkerHandler struct {
	clusterInteractor *cluster_interaction.ClusterInteraction
	informerFactory   informers.SharedInformerFactory
	registrarClient   *registrar.Client
	agentConfig       *model.AgentConfig
	agentClient       *agent.Client
	whitelistClient   *whitelist.Client
}

func (wh *WorkerHandler) Init(attestationEnabledNamespaces []string, defaultResync int, registrarClient *registrar.Client, agentConfig *model.AgentConfig) {
	wh.clusterInteractor.AttestationEnabledNamespaces = attestationEnabledNamespaces
	wh.clusterInteractor.ConfigureKubernetesClient()
	wh.informerFactory = informers.NewSharedInformerFactory(wh.clusterInteractor.ClientSet, time.Minute*time.Duration(defaultResync))
	wh.registrarClient = registrarClient
	wh.agentConfig = agentConfig
}

func (wh *WorkerHandler) SetAgentClient(agentClient *agent.Client) {
	wh.agentClient = agentClient
}

func (wh *WorkerHandler) addNodeHandling(obj interface{}) {
	node := obj.(*corev1.Node)

	isControlPlane, err := wh.clusterInteractor.NodeIsControlPlane("", node)
	if err != nil {
		logger.Error("Failed to determine if node '%s' is control-plane: %v", node.GetName(), err)
	}

	if isControlPlane {
		logger.Info("node '%s' is control-plane; skipping registration", node.GetName())
		return
	}

	workerResponse, err := wh.registrarClient.GetWorkerIdByName(node.GetName())
	if err != nil {
		logger.Error("Failed to determine if node '%s' is registered: %v", node.GetName(), err)
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
	wh.agentClient.Init(agentHost, agentPort, nil)

	logger.Info("successfully deployed agent on node '%s'; service port: %d", node.GetName(), agentPort)

	isNewWorkerRegistered := wh.workerRegistration(node, agentDeploymentName)

	isAgentCreated, err := wh.clusterInteractor.CreateAgentCRDInstance(node.GetName())
	if err != nil {
		logger.Error("Failed to create agent CRD instance on node '%s': %v; deleting node from cluster", node.GetName(), err)
	}

	if !createAgentCRDInstance(node.GetName()) || !workerRegistration(node, agentHost, agentPort) {
		err := deleteNodeFromCluster(node.GetName())
		if err != nil {
			fmt.Printf(red.Sprintf("[%s] Failed to delete Worker Node '%s' from the cluster: %v\n", time.Now().Format("02-01-2006 15:04:05"), node.GetName(), err))
		}
	}
}

// workerRegistration registers the worker node by calling the identification API
func (wh *WorkerHandler) workerRegistration(newWorker *corev1.Node, agentDeploymentName string) bool {
	err := wh.clusterInteractor.WaitForPodRunning(cluster_interaction.PodAttestationNamespace, agentDeploymentName, 1*time.Minute)
	if err != nil {
		logger.Error("Error while contacting Agent: %v", err)
		return false
	}

	// Call Agent to identify worker data
	workerData, err := wh.agentClient.WorkerRegistrationCredentials()
	if err != nil {
		logger.Error("Failed to start get worker credentials and identification data: %v", err)
		return false
	}

	// TEST: this allows the agent in 'simulator' mode to be compliant with the framework
	ekCertCheckRequest := model.VerifyTPMEKCertificateRequest{
		EKCertificate: workerData.EKCert,
	}

	ekVerificationResponse, err := wh.registrarClient.VerifyEKCertificate(ekCertCheckRequest)
	if err != nil {
		logger.Error("Failed to verify EK Certificate: %v", err)
		return false
	}
	if ekVerificationResponse.Status != model.Success {
		logger.Error("Invalid EK Certificate: %v", err)
		return false
	}

	ekCert, err := cryptoUtils.LoadCertificateFromPEM(workerData.EKCert)
	if err != nil {
		logger.Error("Failed to load EK Certificate: %v", err)
		return false
	}

	ek := ekCert.PublicKey.(*rsa.PublicKey)

	AIKPublicKey, err := tpm_attestation.ValidateAIKPublicData(workerData.AIKNameData, workerData.AIKPublicArea)
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
	quoteNonce := hex.EncodeToString(ephemeralKey[:8])

	// TODO kdf instead of raw ephemeral key piece

	encodedCredentialBlob, encodedEncryptedSecret, err := tpm_attestation.GenerateCredentialActivation(workerData.AIKNameData, ek, ephemeralKey)
	if err != nil {
		logger.Error("Failed to generate AIK credential activation challenge: %v", err)
		return false
	}

	// Prepare challenge payload for sending
	workerChallenge := model.WorkerChallenge{
		AIKCredential:      encodedCredentialBlob,
		AIKEncryptedSecret: encodedEncryptedSecret,
	}

	// Send challenge request to the agent
	challengeResponse, err := sendChallengeRequest(agentChallengeNodeURL, workerChallenge)
	if err != nil {
		logger.Error("Failed to send challenge request: %v", err)
		return false
	}

	decodedHMAC, err := base64.StdEncoding.DecodeString(challengeResponse.HMAC)
	if err != nil {
		logger.Error("Failed to decode HMAC: %v", err)
		return false
	}

	// Verify the HMAC response from the agent
	err = cryptoUtils.VerifyHMAC([]byte(workerData.UUID), ephemeralKey, decodedHMAC)
	if err != nil {
		logger.Error("Failed to verify HMAC: %v", err)
		return false
	}

	bootAggregate, hashAlg, err := validateWorkerQuote(challengeResponse.WorkerBootQuote, quoteNonce, AIKPublicKey)
	if err != nil {
		logger.Error("Failed to validate Worker Quote: %v", err)
		return false
	}

	workerWhitelistCheckRequest := model.WorkerWhitelistCheckRequest{
		OsName:        newWorker.Status.NodeInfo.OSImage,
		BootAggregate: bootAggregate,
		HashAlg:       hashAlg,
	}

	err = verifyBootAggregate(workerWhitelistCheckRequest)
	if err != nil {
		logger.Error("Worker Boot validation failed: %v", err)
		return false
	}

	AIKPublicKeyPEM := cryptoUtils.EncodePublicKeyToPEM(AIKPublicKey)
	if AIKPublicKeyPEM == nil {
		logger.Error("Failed to parse AIK Public Key to PEM format", err)
		return false
	}

	workerNode := &model.WorkerNode{
		WorkerId: workerData.UUID,
		Name:     newWorker.GetName(),
		AIK:      string(AIKPublicKeyPEM),
	}

	// Create a new worker
	createWorkerResponse, err := wh.registrarClient.CreateWorker(workerNode)
	if err != nil {
		logger.Error("Failed to create Worker Node: %v", err)
	}

	registrationAcknowledge := &model.RegistrationAcknowledge{
		Message: createWorkerResponse.Message,
		Status:  createWorkerResponse.Status,
	}

	if createWorkerResponse.Status == model.Success {
		registrationAcknowledge.VerifierPublicKey = verifierPublicKey
	}

	err = workerRegistrationAcknowledge(agentAcknowledgeURL, registrationAcknowledge)
	if err != nil {
		logger.Error("Failed to acknowledge Worker Node about registration result: %v", err)
		return false
	}

	logger.Success("Successfully registered Worker Node '%s': %s", newWorker.GetName(), workerData.UUID)
	return true
}

func (wh *WorkerHandler) WatchNodes() {
	stopCh := setupSignalHandler()
	// Create an informer factory
	nodeInformer := wh.informerFactory.Core().V1().Nodes().Informer()

	nodeEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    wh.addNodeHandling,
		UpdateFunc: func(old, new interface{}) {},
		DeleteFunc: wh.deleteNodeHandling,
	}

	// Add event handlers for Node events
	_, err := nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}
			handleNodeAdd(node)
		},
		DeleteFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}
			handleNodeDelete(node)
		},
	})

	// Convert `chan os.Signal` to `<-chan struct{}`
	stopStructCh := make(chan struct{})
	go func() {
		<-stopCh // Wait for signal
		close(stopStructCh)
	}()

	// Start the informer
	go nodeInformer.Run(stopStructCh)

	// Wait for the informer to sync
	if !cache.WaitForCacheSync(stopStructCh, nodeInformer.HasSynced) {
		fmt.Println("Timed out waiting for caches to sync")
		return
	}

	// Keep running until stopped
	<-stopStructCh
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}
