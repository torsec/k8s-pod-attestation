package cluster_interaction

import (
	"context"
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	"path/filepath"
	"sigs.k8s.io/yaml"
	"strconv"
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

const (
	AgentServicePort int32 = 9090
)

const (
	ControlPlaneLabel = "node-role.kubernetes.io/control-plane"
)

//var agentNodePortAllocation int32 = 31000

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

// NodeIsControlPlane check if node being considered is Control Plane; if node is already available just check for the control plane label presence, otherwise fetch the node
// with provided name
func (c *ClusterInteraction) NodeIsControlPlane(nodeName string, node *v1.Node) (bool, error) {
	var err error
	if node == nil {
		node, err = c.ClientSet.CoreV1().Nodes().Get(context.TODO(), nodeName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to get node: %v", err)
		}
	}
	_, exists := node.Labels[ControlPlaneLabel]
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
	podSelector := fmt.Sprintf("metadata.name=%s", podName)
	// Get all pods
	pods, err := c.ClientSet.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: podSelector,
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

	attestationRequestName := fmt.Sprintf("attestation-request-%s", podName)

	// Create an unstructured object to represent the AttestationRequest
	attestationRequest := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": APIVersion,
			"kind":       Kind,
			"metadata": map[string]interface{}{
				"name": attestationRequestName, // Unique name for the custom resource
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

func (c *ClusterInteraction) CheckAgentCRD(agentCRDName, podName, tenantId string) (bool, error) {
	// Define the GVR (GroupVersionResource) for the CRD you want to watch
	gvr := schema.GroupVersionResource{
		Group:    AgentCRDGroup,
		Version:  AgentCRDVersion,
		Resource: AgentCRDResource,
	}

	// Use the dynamic client to get the CRD by name
	crd, err := c.DynamicClient.Resource(gvr).Namespace(PodAttestationNamespace).Get(context.TODO(), agentCRDName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to retrieve Agent CRD: %v", err)
	}

	// Example: Access a specific field in the spec (assuming CRD has a "spec" field)
	if podStatus, found, err := unstructured.NestedSlice(crd.Object, "spec", "podStatus"); found && err == nil {
		for _, ps := range podStatus {
			pod := ps.(map[string]interface{})
			// check if Pod belongs to calling Tenant
			if pod["podName"].(string) == podName && pod["tenantId"].(string) == tenantId {
				return true, nil
			}
		}
	} else if err != nil {
		return false, fmt.Errorf("error retrieving 'podStatus'")
	} else {
		return false, fmt.Errorf("'podStatus' field not found")
	}
	return false, fmt.Errorf("failed to retrieve requested pod: %s in the Agent CRD: %s", podName, agentCRDName)
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

func (c *ClusterInteraction) GetWorkerInternalIP(worker *v1.Node) (string, error) {
	// Loop through the addresses of the node to find the InternalIP (within the cluster)
	var workerIP string
	for _, address := range worker.Status.Addresses {
		if address.Type == v1.NodeInternalIP {
			workerIP = address.Address
			break
		}
	}
	if workerIP == "" {
		return "", fmt.Errorf("no internal IP found for node '%s'", worker.GetName())
	}
	return workerIP, nil
}

func (c *ClusterInteraction) DeployAgent(newWorker *v1.Node, TPMPath, IMAMountPath, IMAMeasurementLogPath, agentImage string, agentPort int32, agentNodePortAllocation *int32) (bool, string, int, error) {
	agentReplicas := int32(1)
	privileged := true
	charDeviceType := v1.HostPathCharDev
	pathFileType := v1.HostPathFile
	agentDeploymentName := fmt.Sprintf("agent-%s-deployment", newWorker.GetName())
	agentContainerName := fmt.Sprintf("agent-%s", newWorker.GetName())
	agentServiceName := fmt.Sprintf("agent-%s-service", newWorker.GetName())

	agentHost, err := c.GetWorkerInternalIP(newWorker)
	if err != nil {
		return false, "", -1, fmt.Errorf("failed to get node '%s' internal IP address: %v", newWorker.GetName(), err)
	}

	agentNodePort := *agentNodePortAllocation

	// Define the Deployment
	agentDeployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agentDeploymentName,
			Namespace: PodAttestationNamespace,
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &agentReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "agent",
				},
			},
			Template: v1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "agent",
					},
				},
				Spec: v1.PodSpec{
					Containers: []v1.Container{
						{
							Name:  agentContainerName,
							Image: agentImage, //"franczar/k8s-attestation-agent:latest"
							Env: []v1.EnvVar{
								{Name: "AGENT_PORT", Value: strconv.Itoa(int(agentPort))},
								{Name: "TPM_PATH", Value: TPMPath},
							},
							Ports: []v1.ContainerPort{
								{ContainerPort: agentPort},
							},
							VolumeMounts: []v1.VolumeMount{
								{Name: "tpm-device", MountPath: TPMPath},
								{Name: "ima-measurements", MountPath: IMAMountPath, ReadOnly: true},
							},
							SecurityContext: &v1.SecurityContext{
								Privileged: &privileged,
							},
						},
					},
					Volumes: []v1.Volume{
						{
							Name: "tpm-device",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: TPMPath,
									Type: &charDeviceType,
								},
							},
						},
						{
							Name: "ima-measurements",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: IMAMeasurementLogPath,
									Type: &pathFileType,
								},
							},
						},
					}, // Ensure pod is deployed on the new worker node
					NodeSelector: map[string]string{
						"kubernetes.io/hostname": newWorker.GetName(),
					},
				},
			},
		},
	}

	// Define the Service
	agentService := &v1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      agentServiceName,
			Namespace: PodAttestationNamespace,
		},
		Spec: v1.ServiceSpec{
			Selector: map[string]string{
				"app": "agent",
			},
			Ports: []v1.ServicePort{
				{
					Protocol:   v1.ProtocolTCP,
					Port:       AgentServicePort,
					TargetPort: intstr.FromInt32(AgentServicePort),
					NodePort:   agentNodePort,
				},
			},
			Type: v1.ServiceTypeNodePort,
		},
	}

	// Deploy the Deployment
	_, err = c.ClientSet.AppsV1().Deployments(PodAttestationNamespace).Create(context.TODO(), agentDeployment, metav1.CreateOptions{})
	if err != nil {
		return false, "", -1, fmt.Errorf("error creating agent deployment '%s': %v", agentDeployment.Name, err)
	}

	// Deploy the Service
	_, err = c.ClientSet.CoreV1().Services(PodAttestationNamespace).Create(context.TODO(), agentService, metav1.CreateOptions{})
	if err != nil {
		delErr := c.ClientSet.AppsV1().Deployments(PodAttestationNamespace).Delete(context.TODO(), agentDeployment.Name, metav1.DeleteOptions{})
		if delErr != nil {
			return false, "", -1, fmt.Errorf("error creating agent service '%s': %v; error deleting agent deployment '%s': %v", agentService.Name, err, agentDeployment.Name, delErr)
		}
		return false, "", -1, fmt.Errorf("error creating agent service '%s': %v", agentService.Name, err)
	}

	*agentNodePortAllocation += 1
	return true, agentHost, int(agentNodePort), nil
}
