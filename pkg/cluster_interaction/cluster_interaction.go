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
