package cluster_status_controller

import (
	"context"
	"fmt"
	clusterInteraction "github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type ClusterStatusController struct {
	clusterInteractor clusterInteraction.ClusterInteraction
	informerFactory   dynamicinformer.DynamicSharedInformerFactory
}

func (csc *ClusterStatusController) Init(defaultResync int) {
	csc.clusterInteractor.ConfigureKubernetesClient()
	csc.informerFactory = dynamicinformer.NewFilteredDynamicSharedInformerFactory(csc.clusterInteractor.DynamicClient, time.Minute*time.Duration(defaultResync), clusterInteraction.PodAttestationNamespace, nil)
}

func (csc *ClusterStatusController) addAgentCRDHandling(obj interface{}) {
	csc.checkAgentStatus(obj)
}

func (csc *ClusterStatusController) updateAgentCRDHandling(oldObj, newObj interface{}) {
	csc.checkAgentStatus(newObj)
}

func (csc *ClusterStatusController) deleteAgentCRDHandling(obj interface{}) {
	csc.checkAgentStatus(obj)
}

func extractNodeName(agentName string) (string, error) {
	// Define the prefix that precedes the nodeName
	prefix := "agent-"

	// Check if the agentName starts with the prefix
	if len(agentName) > len(prefix) && agentName[:len(prefix)] == prefix {
		// Extract the nodeName by removing the prefix
		nodeName := agentName[len(prefix):]
		return nodeName, nil
	}

	// Return an error if the agentName does not start with the expected prefix
	return "", fmt.Errorf("invalid 'agentName' format: %s", agentName)
}

func (csc *ClusterStatusController) WatchAgentCRDs() {
	ctx := setupSignalHandler()

	// Get the informer for the CRD
	agentInformer := csc.informerFactory.ForResource(clusterInteraction.AgentGVR).Informer()

	// Add event handlers
	_, err := agentInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    csc.addAgentCRDHandling,
		UpdateFunc: csc.updateAgentCRDHandling,
		DeleteFunc: csc.deleteAgentCRDHandling,
	})

	if err != nil {
		logger.Fatal("failed to create Agent CRD event handler: %v", err)
	}

	// Start the informer
	go agentInformer.Run(ctx.Done())

	// Wait for the informer to sync
	if !cache.WaitForCacheSync(ctx.Done(), agentInformer.HasSynced) {
		logger.Error("timed out waiting for caches to sync")
		return
	}

	// Keep running until stopped
	<-ctx.Done()
	logger.Info("stopping Cluster Status Controller...")
}

func (csc *ClusterStatusController) checkAgentStatus(obj interface{}) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		logger.Error("expected *unstructured.Unstructured but got %T", obj)
		return
	}

	var agent clusterInteraction.Agent
	err := agent.FromUnstructured(unstructuredObj)
	if err != nil {
		logger.Error("failed to parse attestation request: %v", err)
		return
	}

	if agent.Spec.NodeStatus == model.UntrustedNodeStatus {
		nodeName, err := extractNodeName(agent.Spec.AgentName)
		if err != nil {
			logger.Error("invalid 'agentName' format: '%s'", agent.Spec.AgentName)
			return
		}

		_, err = csc.clusterInteractor.DeleteAllPodsFromNode(nodeName)
		if err != nil {
			logger.Error("failed to delete pods from node: %v", err)
			return
		}

		_, err = csc.clusterInteractor.DeleteNode(nodeName)
		if err != nil {
			logger.Error("failed to delete node: %v", err)
			return
		}
		return
	}

	for _, pod := range agent.Spec.PodStatus {
		if pod.Status == model.UntrustedPodStatus {
			logger.Warning("detected untrusted pod: '%s'", pod.PodName)
			_, err := csc.clusterInteractor.DeletePod(pod.PodName)
			if err != nil {
				logger.Error("error deleting pod '%s': %v", pod.PodName, err)
			}
			logger.Success("untrusted pod: '%s' successfully deleted", pod.PodName)
		}
	}
	logger.Info("trust status for agent '%s': '%s'", agent.Spec.AgentName, agent.Spec)
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
