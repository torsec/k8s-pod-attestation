package cluster_interaction

import (
	"context"
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	v1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
)

type ClusterInteraction struct {
	ClientSet                    *kubernetes.Clientset
	DynamicClient                dynamic.Interface
	AttestationEnabledNamespaces []string
}

// Pod status possible values
const (
	NewPodStatus            = "NEW"
	TrustedPodStatus        = "TRUSTED"
	UntrustedPodStatus      = "UNTRUSTED"
	UnknownPodStatus        = "UNKNOWN"
	DeletedPodStatus        = "DELETED"
	PodAttestationNamespace = "attestation-system"
)

// Agent CRD parameters
const (
	AgentCRDGroup    = "example.com"
	AgentCRDVersion  = "v1"
	AgentCRDResource = "agents"
)

// ConfigureKubernetesClient initializes the Kubernetes client by retrieving the kubeconfig file from home directory of current user under /.kube/config
func (c *ClusterInteraction) ConfigureKubernetesClient() {
	var err error
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			logger.Fatal("Failed to build config from kubeconfig: %v", err)
		}
	}
	c.DynamicClient, err = dynamic.NewForConfig(config)
	if err != nil {
		logger.Fatal("Failed to create Kubernetes dynamic client: %v", err)
	}
	c.ClientSet, err = kubernetes.NewForConfig(config)
	if err != nil {
		logger.Fatal("Failed to create Kubernetes client: %v", err)
	}
}

// NodeIsControlPlane check if node being considered is Control Plane
func (c *ClusterInteraction) NodeIsControlPlane(nodeName string) (bool, error) {
	// Get the node object to check for control plane label
	node, err := c.ClientSet.CoreV1().Nodes().Get(context.TODO(), nodeName, v1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get node: %v", err)
	}
	// Check if the node is a control plane node
	_, exists := node.Labels["node-role.kubernetes.io/control-plane"]
	return exists, nil
}

// IsNamespaceEnabledForAttestation checks if the given podNamespace is enabled for attestation
func (c *ClusterInteraction) IsNamespaceEnabledForAttestation(podNamespace string) bool {
	for _, ns := range c.AttestationEnabledNamespaces {
		if ns == podNamespace {
			return true
		}
	}
	return false
}

func (c *ClusterInteraction) DeleteNode(nodeName string) (bool, error) {
	// Delete the node
	err := c.ClientSet.CoreV1().Nodes().Delete(context.TODO(), nodeName, v1.DeleteOptions{})
	if err != nil {
		logger.Error("error deleting node '%s': %v", nodeName, err)
		return false, fmt.Errorf("error deleting node '%s': %v", nodeName, err)
	}
	return true, nil
}

func (c *ClusterInteraction) DeletePod(podName string) (bool, error) {
	// Get all pods
	pods, err := c.ClientSet.CoreV1().Pods("").List(context.TODO(), v1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", podName),
	})
	if err != nil {
		return false, fmt.Errorf("error deleting pod '%s': %v", podName, err)
	}

	// Delete each pod on the node
	for _, pod := range pods.Items {
		err := c.ClientSet.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, v1.DeleteOptions{})
		if err != nil {
			return false, fmt.Errorf("error deleting pod '%s': %v", pod.Name, err)
		}
	}

	return true, nil
}

func (c *ClusterInteraction) DeleteAllPodsFromNode(nodeName string) (bool, error) {
	// Get all pods on the specified node
	pods, err := c.ClientSet.CoreV1().Pods("").List(context.TODO(), v1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		return false, fmt.Errorf("error deleting pods from node '%s': %v", nodeName, err)
	}

	// Delete each pod on the node
	for _, pod := range pods.Items {
		err := c.ClientSet.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, v1.DeleteOptions{})
		if err != nil {
			return false, fmt.Errorf("error deleting pod '%s' from node '%s': %v", pod.Name, nodeName, err)
		}
		logger.Success("Deleted pod '%s' from node '%s'", pod.Name, nodeName)
	}
	return true, nil
}
