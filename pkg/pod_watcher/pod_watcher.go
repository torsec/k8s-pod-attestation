package pod_watcher

import (
	"context"
	clusterInteraction "github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	corev1 "k8s.io/api/core/v1"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

type PodWatcher struct {
	clusterInteractor clusterInteraction.ClusterInteraction
	informerFactory   informers.SharedInformerFactory
}

func (pw *PodWatcher) Init(attestationEnabledNamespaces []string, defaultResync int) {
	pw.clusterInteractor.ConfigureKubernetesClient()
	pw.clusterInteractor.AttestationEnabledNamespaces = attestationEnabledNamespaces
	pw.informerFactory = informers.NewSharedInformerFactory(pw.clusterInteractor.ClientSet, time.Minute*time.Duration(defaultResync))
}

func (pw *PodWatcher) updatePodHandling(oldObj interface{}, newObj interface{}) {
	oldPod := oldObj.(*corev1.Pod)
	newPod := newObj.(*corev1.Pod)

	isOldNamespaceEnabled := pw.clusterInteractor.IsNamespaceEnabledForAttestation(oldPod.GetNamespace())
	isNewNamespaceEnabled := pw.clusterInteractor.IsNamespaceEnabledForAttestation(newPod.GetNamespace())

	if !isOldNamespaceEnabled && !isNewNamespaceEnabled {
		return
	}

	if oldPod.Spec.NodeName != "" && newPod.Spec.NodeName != "" && oldPod.Spec.NodeName == newPod.Spec.NodeName && oldPod.GetNamespace() == newPod.GetNamespace() {
		// Pod is already tracked
		return
	}

	if oldPod.Spec.NodeName == "" && newPod.Spec.NodeName != "" && isNewNamespaceEnabled {
		podStatus := model.NewPodStatus
		reason := "Pod first time scheduled to a node"
		err := pw.clusterInteractor.UpdatePodStatus(newPod.Spec.NodeName, newPod.Name, newPod.Annotations["tenantId"], reason, podStatus)
		if err != nil {
			logger.Error("error occurred while updating pod status for pod '%s': %v", newPod.Name, err)
		}
		logger.Success("pod '%s' scheduled to node '%s'; starting pod attestation tracking", newPod.Name, newPod.Spec.NodeName)
	}

	if oldPod.Spec.NodeName != "" && newPod.Spec.NodeName != "" && oldPod.Spec.NodeName != newPod.Spec.NodeName {
		pw.changePodAgent(oldPod, newPod)
		return
	}
}

func (pw *PodWatcher) addPodHandling(obj interface{}) {
	pod := obj.(*corev1.Pod)
	podNamespace := pod.GetNamespace()
	podName := pod.GetName()
	nodeName := pod.Spec.NodeName

	podStatus := model.NewPodStatus
	reason := "New pod added to the cluster"

	isNamespaceEnabled := pw.clusterInteractor.IsNamespaceEnabledForAttestation(podNamespace)
	if !isNamespaceEnabled {
		logger.Info("namespace '%s' is not enabled for pod attestation; skipping attestation tracking for pod '%s'", podNamespace, podName)
		return
	}

	if nodeName == "" {
		logger.Info("pod '%s' not scheduled yet; pod attestation tracking will start after the pod is scheduled on a worker node", podName)
		return
	}

	isNodeControlPlane, err := pw.clusterInteractor.NodeIsControlPlane(nodeName, nil)
	if err != nil {
		logger.Error("error occurred while checking if node is control plane: %v; skipping attestation tracking for pod '%s'", err, podName)
		podStatus = model.UnknownPodStatus
		return
	}

	if isNodeControlPlane {
		logger.Info("node '%s' is control-plane; skipping attestation tracking for pod '%s'", nodeName, podName)
		return
	}

	err = pw.clusterInteractor.UpdatePodStatus(nodeName, podName, pod.Annotations["tenantId"], reason, podStatus)
	if err != nil {
		logger.Error("error occurred while updating pod status for pod '%s': %v", podName, err)
	}
	logger.Success("pod '%s' added to node '%s'; starting pod attestation tracking", podName, nodeName)
}

func (pw *PodWatcher) deletePodHandling(obj interface{}) {
	pod := obj.(*corev1.Pod)
	podNamespace := pod.GetNamespace()
	nodeName := pod.Spec.NodeName

	podStatus := model.DeletedPodStatus
	reason := "Pod deleted"

	isNamespaceEnabled := pw.clusterInteractor.IsNamespaceEnabledForAttestation(podNamespace)
	if !isNamespaceEnabled {
		logger.Info("namespace '%s' is not enabled for pod attestation; skipping ending of pod attestation tracking", podNamespace)
		return
	}

	isNodeControlPlane, err := pw.clusterInteractor.NodeIsControlPlane(nodeName, nil)
	if err != nil {
		logger.Error("error occurred while checking if node is control plane: %v; skipping ending of pod attestation tracking", err)
		// TODO: pod may need to be killed and rescheduled for security reason or retry x times before doing it
		podStatus = model.UnknownPodStatus
		return
	}

	if isNodeControlPlane {
		logger.Info("node '%s' is not a worker; skipping ending of pod attestation tracking", nodeName)
		return
	}

	err = pw.clusterInteractor.UpdatePodStatus(nodeName, pod.Name, pod.Annotations["tenantId"], reason, podStatus)
	if err != nil {
		logger.Error("error occurred while updating pod status for pod '%s': %v", pod.Name, err)
	}
	logger.Success("pod '%s' deleted from node '%s'; ending pod attestation tracking", pod.Name, nodeName)
}

func (pw *PodWatcher) changePodAgent(oldPod, newPod *corev1.Pod) {
	// Pod has been rescheduled to a different node
	oldPodNamespace := newPod.GetNamespace()
	oldPodName := newPod.GetName()
	oldNodeName := oldPod.Spec.NodeName

	newPodNamespace := newPod.GetNamespace()
	newPodName := newPod.GetName()
	newNodeName := newPod.Spec.NodeName
	reason := "Pod rescheduled to a different node"

	isNamespaceEnabled := pw.clusterInteractor.IsNamespaceEnabledForAttestation(oldPodNamespace)
	if isNamespaceEnabled {
		err := pw.clusterInteractor.UpdatePodStatus(oldNodeName, oldPodName, oldPod.Annotations["tenantId"], reason, model.DeletedPodStatus)
		if err != nil {
			logger.Error("error while stopping tracking for pod '%s' on node '%s': %v", oldPodName, oldNodeName, err)
		}
	}

	isNamespaceEnabled = pw.clusterInteractor.IsNamespaceEnabledForAttestation(newPodNamespace)
	if isNamespaceEnabled {
		err := pw.clusterInteractor.UpdatePodStatus(newPodName, newNodeName, oldPod.Annotations["tenantId"], reason, model.NewPodStatus)
		if err != nil {
			logger.Error("error while stopping tracking for pod '%s' on node '%s': %v", oldPodName, oldNodeName, err)
		}
	}
}

func (pw *PodWatcher) WatchPods() {
	ctx := setupSignalHandler()
	podInformer := pw.informerFactory.Core().V1().Pods().Informer()

	podEventHandler := cache.ResourceEventHandlerFuncs{
		AddFunc:    pw.addPodHandling,
		UpdateFunc: pw.updatePodHandling,
		DeleteFunc: pw.deletePodHandling,
	}

	// Add event handlers
	_, err := podInformer.AddEventHandler(podEventHandler)
	if err != nil {
		logger.Fatal("failed to create pod event handler: %v", err)
	}

	// Start the informer
	go podInformer.Run(ctx.Done())

	// Wait for the informer to sync
	if !cache.WaitForCacheSync(ctx.Done(), podInformer.HasSynced) {
		logger.Warning("timed out waiting for caches to sync")
		return
	}

	// Keep running until stopped
	<-ctx.Done()
	logger.Info("stopping PodWatcher...")
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
