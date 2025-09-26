package cluster_status_controller

import (
	"context"
	"fmt"
	clusterInteraction "github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"k8s.io/apimachinery/pkg/runtime"
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
	logger.Info("Agent CRD Added: %s", formatAgentCRD(obj))
}

func (csc *ClusterStatusController) updateAgentCRDHandling(oldObj, newObj interface{}) {
	logger.Info("Agent CRD Modified: %s", formatAgentCRD(newObj))
	csc.checkAgentStatus(newObj)
}

func (csc *ClusterStatusController) deleteAgentCRDHandling(obj interface{}) {
	logger.Info("Agent CRD Deleted: %s", formatAgentCRD(obj))
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
	spec := formatAgentCRD(obj)

	if spec["nodeStatus"] == clusterInteraction.UntrustedPodStatus {
		nodeName, err := extractNodeName(spec["agentName"].(string))
		if err != nil {
			logger.Error("invalid 'agentName' format: '%s'", spec["agentName"])
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

	podStatusInterface, exists := spec["podStatus"]
	if !exists {
		logger.Error("missing 'podStatus' field in Agent CRD")
		return
	}

	podStatus, ok := podStatusInterface.([]interface{})
	if !ok {
		logger.Error("unable to parse 'podStatus' field in Agent CRD")
		return
	}

	for _, ps := range podStatus {
		pod := ps.(map[string]interface{})
		podName, ok := pod["podName"].(string)
		if !ok {
			logger.Error("unable to parse 'podName' field in 'podStatus'")
			continue
		}
		status, ok := pod["status"].(string)
		if !ok {
			logger.Error("unable to parse 'status' field in 'podStatus'")
			continue
		}

		if status == clusterInteraction.UntrustedPodStatus {
			logger.Warning("detected untrusted pod: '%s'", podName)
			_, err := csc.clusterInteractor.DeletePod(podName)
			if err != nil {
				logger.Error("error deleting pod '%s': %v", podName, err)
			}
			logger.Success("untrusted pod: '%s' successfully deleted", podName)
		}
	}
}

func formatAgentCRD(obj interface{}) map[string]interface{} {
	agentCRD, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		logger.Error("missing 'spec' field in Agent CRD")
		return nil
	}

	spec, specExists := agentCRD["spec"].(map[string]interface{})
	if !specExists {
		logger.Error("missing 'spec' field in Agent CRD")
		return nil
	}
	return spec
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
