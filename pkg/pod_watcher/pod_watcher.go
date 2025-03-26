package pod_watcher

import (
	"context"
	clusterInteraction "github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type PodWatcher struct {
	clusterInteractor *clusterInteraction.ClusterInteraction
	informerFactory   informers.SharedInformerFactory
}

func (pw *PodWatcher) Init(attestationEnabledNamespaces []string, defaultResync int) {
	pw.clusterInteractor.AttestationEnabledNamespaces = attestationEnabledNamespaces
	pw.clusterInteractor.ConfigureKubernetesClient()
	pw.informerFactory = informers.NewSharedInformerFactory(pw.clusterInteractor.ClientSet, time.Minute*time.Duration(defaultResync))
}

func (pw *PodWatcher) addPodHandling(obj interface{}) {
	pod := obj.(*corev1.Pod)
	podNamespace := pod.GetNamespace()
	nodeName := pod.Spec.NodeName
	podName := pod.GetName()

	var podStatus string

	isNamespaceEnabled := pw.clusterInteractor.IsNamespaceEnabledForAttestation(podNamespace)
	if !isNamespaceEnabled {
		logger.Info("namespace '%s' is not enabled for pod attestation; skipping attestation tracking for pod '%s'", podNamespace, podName)
		return
	}

	isNodeControlPlane, err := pw.clusterInteractor.NodeIsControlPlane(nodeName)
	if err != nil {
		logger.Error("error occurred while checking if node is control plane: %v; skipping attestation tracking for pod '%s'", err, podName)
		podStatus = clusterInteraction.UnknownPodStatus
	}

	if isNodeControlPlane {
		logger.Info("node '%s' is not a worker; skipping attestation tracking for pod '%s'", nodeName, podName)
		return
	}

	logger.Success("pod '%s' added to node '%s'; starting pod attestation tracking", podName, nodeName)
	podStatus = clusterInteraction.NewPodStatus
	pw.updateAgentCRDWithPodStatus(nodeName, podName, pod.Annotations["tenantId"], podStatus)
}

func (pw *PodWatcher) deletePodHandling(obj interface{}) {
	pod := obj.(*corev1.Pod)
	podNamespace := pod.GetNamespace()
	nodeName := pod.Spec.NodeName

	var podStatus string

	isNamespaceEnabled := pw.clusterInteractor.IsNamespaceEnabledForAttestation(podNamespace)
	if !isNamespaceEnabled {
		logger.Info("namespace '%s' is not enabled for pod attestation; skipping ending of pod attestation tracking", podNamespace)
		return
	}

	isNodeControlPlane, err := pw.clusterInteractor.NodeIsControlPlane(nodeName)
	if err != nil {
		logger.Error("error occurred while checking if node is control plane: %v; skipping ending of pod attestation tracking", err)
		// TODO: pod may need to be killed and rescheduled for security reason or retry x times before doing it
		podStatus = clusterInteraction.UnknownPodStatus
	}

	if isNodeControlPlane {
		logger.Info("node '%s' is not a worker; skipping ending of pod attestation tracking", nodeName)
		return
	}

	logger.Success("pod '%s' deleted from node '%s'; ending pod attestation tracking", pod.Name, nodeName)
	podStatus = clusterInteraction.DeletedPodStatus
	pw.updateAgentCRDWithPodStatus(nodeName, pod.Name, pod.Annotations["tenantId"], podStatus)
}

func (pw *PodWatcher) WatchPods() {
	stopCh := setupSignalHandler()
	podInformer := pw.informerFactory.Core().V1().Pods().Informer()

	podEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    pw.addPodHandling,
		UpdateFunc: func(oldObj, newObj interface{}) {}, // Update is not relevant, we just care of pods addition and removal
		DeleteFunc: pw.deletePodHandling,
	}

	// Add event handlers
	_, err := podInformer.AddEventHandler(podEventHandler)
	if err != nil {
		logger.Fatal("failed to create pod event handler: %v", err)
	}

	// Convert `chan os.Signal` to `<-chan struct{}`
	stopStructCh := make(chan struct{})
	go func() {
		<-stopCh // Wait for signal
		close(stopStructCh)
	}()

	// Start the informer
	go podInformer.Run(stopStructCh)

	// Wait for the informer to sync
	if !cache.WaitForCacheSync(stopStructCh, podInformer.HasSynced) {
		logger.Warning("timed out waiting for caches to sync")
		return
	}

	// Keep running until stopped
	<-stopStructCh
	logger.Info("stopping PodWatcher...")
}

func (pw *PodWatcher) updateAgentCRDWithPodStatus(nodeName, podName, tenantId, status string) {
	agentCRDName := "agent-" + nodeName
	// Get the current CRD instance
	crdResource := pw.clusterInteractor.DynamicClient.Resource(schema.GroupVersionResource{
		Group:    clusterInteraction.AgentCRDGroup,
		Version:  clusterInteraction.AgentCRDVersion,
		Resource: clusterInteraction.AgentCRDResource,
	}).Namespace(clusterInteraction.PodAttestationNamespace)

	crdInstance, err := crdResource.Get(context.Background(), agentCRDName, v1.GetOptions{})
	if err != nil {
		logger.Warning("error getting Agent CRD instance: %v", err)
		return
	}

	// Initialize 'podStatus' as an empty slice of interfaces if it's nil
	spec := crdInstance.Object["spec"].(map[string]interface{})
	podStatus := spec["podStatus"]
	if podStatus == nil {
		spec["podStatus"] = make([]interface{}, 0)
	}

	// Update the pod status in the CRD
	newPodStatus := make([]interface{}, 0)
	for _, ps := range spec["podStatus"].([]interface{}) {
		pod := ps.(map[string]interface{})
		if pod["podName"].(string) != podName {
			newPodStatus = append(newPodStatus, ps)
		}
	}

	now := time.Now().Format(time.RFC3339)

	if status != clusterInteraction.DeletedPodStatus {
		newPodStatus = append(newPodStatus, map[string]interface{}{
			"podName":   podName,
			"tenantId":  tenantId,
			"status":    status,
			"reason":    "Pod just created",
			"lastCheck": now,
		})
	}

	spec["podStatus"] = newPodStatus
	spec["lastUpdate"] = now
	crdInstance.Object["spec"] = spec

	// Update the CRD instance
	_, err = crdResource.Update(context.Background(), crdInstance, v1.UpdateOptions{})
	if err != nil {
		logger.Error("error updating Agent CRD '%s': %v", agentCRDName, err)
		return
	}

	logger.Success("Agent CRD '%s' updated; involved pod: '%s'", agentCRDName, podName)
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}
