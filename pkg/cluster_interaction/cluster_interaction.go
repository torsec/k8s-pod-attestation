package cluster_interaction

import (
	"context"
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
	"sigs.k8s.io/yaml"
	"time"
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
	APIVersion       = AgentCRDGroup + "/" + AgentCRDVersion
	Kind             = "AttestationRequest"
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

func (c *ClusterInteraction) CreateTenantPodFromManifest(podManifest []byte, tenantId string) (*v1.Pod, error) {
	var pod *v1.Pod

	if err := yaml.Unmarshal(podManifest, &pod); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	pod.Annotations["tenantId"] = tenantId

	podsClient := c.ClientSet.CoreV1().Pods(pod.Namespace)
	createdPod, err := podsClient.Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create Pod: %v", err)
	}
	return createdPod, nil
}

// NodeIsControlPlane check if node being considered is Control Plane
func (c *ClusterInteraction) NodeIsControlPlane(nodeName string) (bool, error) {
	// Get the node object to check for control plane label
	node, err := c.ClientSet.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
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
	err := c.ClientSet.CoreV1().Nodes().Delete(context.TODO(), nodeName, metav1.DeleteOptions{})
	if err != nil {
		return false, fmt.Errorf("error deleting node '%s': %v", nodeName, err)
	}
	return true, nil
}

func (c *ClusterInteraction) DeletePod(podName string) (bool, error) {
	// Get all pods
	pods, err := c.ClientSet.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("metadata.name=%s", podName),
	})
	if err != nil {
		return false, fmt.Errorf("error deleting pod '%s': %v", podName, err)
	}

	// Delete each pod on the node
	for _, pod := range pods.Items {
		err := c.ClientSet.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
		if err != nil {
			return false, fmt.Errorf("error deleting pod '%s': %v", pod.Name, err)
		}
	}

	return true, nil
}

func (c *ClusterInteraction) DeleteAllPodsFromNode(nodeName string) (bool, error) {
	// Get all pods on the specified node
	pods, err := c.ClientSet.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		return false, fmt.Errorf("error deleting pods from node '%s': %v", nodeName, err)
	}

	// Delete each pod on the node
	for _, pod := range pods.Items {
		err := c.ClientSet.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
		if err != nil {
			return false, fmt.Errorf("error deleting pod '%s' from node '%s': %v", pod.Name, nodeName, err)
		}
		logger.Success("Deleted pod '%s' from node '%s'", pod.Name, nodeName)
	}
	return true, nil
}

func (c *ClusterInteraction) IssueAttestationRequestCRD(podName, podUID, tenantId, agentName, agentIP, hmac string) (bool, error) {
	gvr := schema.GroupVersionResource{
		Group:    AgentCRDGroup,
		Version:  AgentCRDVersion,
		Resource: AgentCRDResource,
	}

	// Create an unstructured object to represent the AttestationRequest
	attestationRequest := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": APIVersion,
			"kind":       Kind,
			"metadata": map[string]interface{}{
				"name": fmt.Sprintf("attestation-request-%s", podName), // Unique name for the custom resource
			},
			"spec": map[string]interface{}{
				"podName":   podName,
				"podUID":    podUID,
				"tenantId":  tenantId,
				"agentName": agentName,
				"agentIP":   agentIP,
				"issued":    time.Now().Format(time.RFC3339), // Current timestamp in RFC3339 format
				"hmac":      hmac,
			},
		},
	}

	// Create the AttestationRequest CR in the attestation namespace
	_, err := c.DynamicClient.Resource(gvr).Namespace(PodAttestationNamespace).Create(context.TODO(), attestationRequest, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to create attestation request: %v", err)
	}
	return true, nil
}

func (c *ClusterInteraction) CheckAgentCRD(agentCRDName, podName, tenantId string) error {
	// Define the GVR (GroupVersionResource) for the CRD you want to watch
	gvr := schema.GroupVersionResource{
		Group:    AgentCRDGroup,
		Version:  AgentCRDVersion,
		Resource: AgentCRDResource,
	}

	// Use the dynamic client to get the CRD by name
	crd, err := c.DynamicClient.Resource(gvr).Namespace(PodAttestationNamespace).Get(context.TODO(), agentCRDName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to retrieve Agent CRD: %v", err)
	}

	// Example: Access a specific field in the spec (assuming CRD has a "spec" field)
	if podStatus, found, err := unstructured.NestedSlice(crd.Object, "spec", "podStatus"); found && err == nil {
		for _, ps := range podStatus {
			pod := ps.(map[string]interface{})
			// check if Pod belongs to calling Tenant
			if pod["podName"].(string) == podName && pod["tenantId"].(string) == tenantId {
				return nil
			}
		}
	} else if err != nil {
		return fmt.Errorf("error retrieving 'podStatus'")
	} else {
		return fmt.Errorf("'podStatus' field not found")
	}
	return fmt.Errorf("failed to retrieve requested pod: %s in the Agent CRD: %s", podName, agentCRDName)
}

func (c *ClusterInteraction) GetAttestationInformation(podName string) (string, string, string, error) {
	// Retrieve the Pod from the Kubernetes API
	podList, err := c.ClientSet.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to retrieve pods: %v", err)
	}

	var podToAttest v1.Pod
	// Iterate over the list of Pods and find the one matching the podName
	for _, pod := range podList.Items {
		if pod.Name == podName {
			podToAttest = pod
			break
		}
	}

	// Check if the pod is in a Running state
	if podToAttest.Status.Phase != v1.PodRunning {
		return "", "", "", fmt.Errorf("pod: '%s' is not running", podName)
	}

	podUID := podToAttest.GetUID()
	nodeName := podToAttest.Spec.NodeName

	// Retrieve the Node information using the nodeName
	node, err := c.ClientSet.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
	if err != nil {
		return "", "", "", fmt.Errorf("failed to retrieve node '%s': %v", nodeName, err)
	}

	// Loop through the addresses of the node to find the InternalIP (within the cluster)
	var agentIP string
	for _, address := range node.Status.Addresses {
		if address.Type == v1.NodeInternalIP {
			agentIP = address.Address
			break
		}
	}

	if agentIP == "" {
		return "", "", "", fmt.Errorf("no internal IP found for node: %s", nodeName)
	}

	return nodeName, agentIP, string(podUID), nil
}
