package pod_watcher

import (
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
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
	ClusterInteractor *k8s_cluster_interaction.ClusterInteraction
}


func (pw *PodWatcher) WatchPods() {
	stopCh := setupSignalHandler()
	// Create a SharedInformerFactory for Pods
	informerFactory := informers.NewSharedInformerFactory(clientset, time.Minute*5)

	// Get the Pod informer
	podInformer := informerFactory.Core().V1().Pods().Informer()

	podEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			podNamespace := pod.GetNamespace()
			nodeName := pod.Spec.NodeName

			if !isNamespaceEnabledForAttestation(podNamespace) || nodeIsControlPlane(nodeName) {
				return
			}

			logger.Success("Pod '%s' added to node '%s'", pod.Name, nodeName)
			updateAgentCRDWithPodStatus(nodeName, pod.Name, pod.Annotations["tenantID"], "TRUSTED")
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			// Handle Pod updates if needed
			// Example: Compare oldObj and newObj states and logger changes
		},
		DeleteFunc: func(obj interface{}) {
			pod := obj.(*corev1.Pod)
			podNamespace := pod.GetNamespace()
			nodeName := pod.Spec.NodeName

			if !isNamespaceEnabledForAttestation(podNamespace) || nodeIsControlPlane(nodeName) {
				return
			}

			logger.Success("Pod '%s' deleted from node '%s'", pod.Name, nodeName))
			updateAgentCRDWithPodStatus(nodeName, pod.Name, pod.Annotations["tenantID"], "DELETED")
		},
	}

	// Add event handlers
	_, err := podInformer.AddEventHandler(podEventHandler)
	if err != nil {
		logger.Fatal("Failed to create pod event handler: %v", err)
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
		fmt.Println("Timed out waiting for caches to sync")
		return
	}

	// Keep running until stopped
	<-stopStructCh
	fmt.Println("Stopping Pod watcher...")
}

func updateAgentCRDWithPodStatus(nodeName, podName, tenantId, status string) {
	// Get the current CRD instance
	crdResource := dynamicClient.Resource(schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "agents",
	}).Namespace("attestation-system")
	crdInstance, err := crdResource.Get(context.Background(), "agent-"+nodeName, v1.GetOptions{})
	if err != nil {
		logger.Warning("Error getting Agent CRD instance: %v", err)
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

	if status != "DELETED" {
		newPodStatus = append(newPodStatus, map[string]interface{}{
			"podName":   podName,
			"tenantID":  tenantId,
			"status":    status,
			"reason":    "Pod just created",
			"lastCheck": time.Now().Format(time.RFC3339),
		})
	}

	spec["podStatus"] = newPodStatus
	spec["lastUpdate"] = time.Now().Format(time.RFC3339)
	crdInstance.Object["spec"] = spec

	// Update the CRD instance
	_, err = crdResource.Update(context.Background(), crdInstance, v1.UpdateOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("Error updating Agent CRD instance: %v\n", err))
		return
	}

	fmt.Printf(green.Sprintf("[%s] Agent CRD 'agent-%s' updated. Involved Pod: %s\n", time.Now().Format("02-01-2006 15:04:05"), nodeName, podName))
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}