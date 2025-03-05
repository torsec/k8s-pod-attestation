package whitelist_provider

import (
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type WorkerHandler struct {
	clusterInteractor *cluster_interaction.ClusterInteraction
	informerFactory   informers.SharedInformerFactory
	registrarClient   *registrar.Client
	agentConfig       *model.AgentConfig
}

func (wh *WorkerHandler) Init(attestationEnabledNamespaces []string, defaultResync int, registrarClient *registrar.Client, agentConfig *model.AgentConfig) {
	wh.clusterInteractor.AttestationEnabledNamespaces = attestationEnabledNamespaces
	wh.clusterInteractor.ConfigureKubernetesClient()
	wh.informerFactory = informers.NewSharedInformerFactory(wh.clusterInteractor.ClientSet, time.Minute*time.Duration(defaultResync))
	wh.registrarClient = registrarClient
	wh.agentConfig = agentConfig
}

func (wh *WorkerHandler) addNodeHandling(obj interface{}) {
	node := obj.(*corev1.Node)

	isControlPlane, err := wh.clusterInteractor.NodeIsControlPlane("", node)
	if err != nil {
		logger.Error("Failed to determine if node '%s' is control-plane: %v", node.Name, err)
	}

	if isControlPlane {
		logger.Info("node '%s' is control-plane; skipping registration", node.Name)
		return
	}

	workerResponse, err := wh.registrarClient.GetWorkerIdByName(node.GetName())
	if err != nil {
		logger.Error("Failed to determine if node '%s' is registered: %v", node.Name, err)
		return
	}

	if workerResponse.Status == registrar.Success {
		logger.Info("node '%s' already registered; skipping registration", node.Name)
		return
	}

	logger.Info("new worker node '%s' joined the cluster: starting registration", node.Name)

	isAgentDeployed, agentHost, agentPort, err := wh.clusterInteractor.DeployAgent(node)
	if err != nil {
		logger.Error("Failed to start Agent on node '%s': %v", node.Name, err)
	}

	logger.Info("successfully deployed agent on node '%s'; service port: %d", node.Name, agentPort)

	if !isAgentDeployed || !createAgentCRDInstance(node.Name) || !workerRegistration(node, agentHOST, agentPORT) {
		err := deleteNodeFromCluster(node.Name)
		if err != nil {
			fmt.Printf(red.Sprintf("[%s] Failed to delete Worker Node '%s' from the cluster: %v\n", time.Now().Format("02-01-2006 15:04:05"), node.Name, err))
		}
	}
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
	fmt.Println("Stopping application...")
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}
