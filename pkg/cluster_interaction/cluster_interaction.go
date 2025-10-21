package cluster_interaction

import (
	"context"
	"fmt"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	appsv1 "k8s.io/api/apps/v1"
	v1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1clientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	"k8s.io/apimachinery/pkg/api/resource"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
	"k8s.io/client-go/util/homedir"
	metricsclient "k8s.io/metrics/pkg/client/clientset/versioned"
	"math"
	"path/filepath"
	"sigs.k8s.io/yaml"
	"strconv"
	"time"
)

type ClusterInteraction struct {
	ClientSet                    *kubernetes.Clientset
	DynamicClient                dynamic.Interface
	ApiExtensionsClient          *apiextensionsv1clientset.Clientset
	MetricsClient                *metricsclient.Clientset
	AttestationEnabledNamespaces []string
}

type AttestationRequestSpec struct {
	PodName   string    `json:"podName"`
	PodUid    string    `json:"podUid"`
	TenantId  string    `json:"tenantId"`
	AgentName string    `json:"agentName"`
	AgentIP   string    `json:"agentIP"`
	Issued    time.Time `json:"issued"`
	HMAC      []byte    `json:"hmac"`
}

type AttestationRequest struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AttestationRequestSpec `json:"spec"`
}

type PodStatus struct {
	PodName   string              `json:"podName"`
	TenantId  string              `json:"tenantId"`
	Status    model.PodStatusType `json:"status"`
	Reason    string              `json:"reason"`
	LastCheck time.Time           `json:"lastCheck"`
}

type AgentSpec struct {
	AgentName  string               `json:"agentName"`
	NodeStatus model.NodeStatusType `json:"nodeStatus"`
	PodStatus  []PodStatus          `json:"podStatus"`
	LastUpdate time.Time            `json:"lastUpdate"`
}

type Agent struct {
	metav1.TypeMeta   `json:",inline"`
	metav1.ObjectMeta `json:"metadata,omitempty"`
	Spec              AgentSpec `json:"spec"`
}

const PodAttestationNamespace = "attestation-system"

// AgentGVR Define the GroupVersionResource for the Agent CRD
var AgentGVR = schema.GroupVersionResource{
	Group:    AgentCRDGroup, // Group name defined in your CRD
	Version:  AgentCRDVersion,
	Resource: AgentCRDResourcePlural, // Plural form of the CRD resource name
}

// AttestationRequestGVR Define the GroupVersionResource (GVR) for your CRD
var AttestationRequestGVR = schema.GroupVersionResource{
	Group:    AttestationRequestCRDGroup,
	Version:  AttestationRequestCRDVersion,
	Resource: AttestationRequestCRDResourcePlural, // plural name of the CRD
}

const KubeSystemNamespace = "kube-system"

// Agent CRD parameters
const (
	AgentCRDName             = "agents.attestation.com"
	AgentCRDGroup            = "attestation.com"
	AgentCRDVersion          = "v1"
	AgentCRDResourcePlural   = "agents"
	AgentCRDListKind         = "AgentList"
	AgentCRDResourceSingular = "agent"
	AgentCRDKind             = "Agent"
	AgentCRDApiVersion       = AgentCRDGroup + "/" + AgentCRDVersion
)

const (
	AttestationRequestCRDName             = "attestationrequests.attestation.com"
	AttestationRequestCRDGroup            = "attestation.com"
	AttestationRequestCRDVersion          = "v1"
	AttestationRequestCRDResourcePlural   = "attestationrequests"
	AttestationRequestCRDResourceSingular = "attestationrequest"
	AttestationRequestCRDListKind         = "AttestationRequestList"
	AttestationRequestCRDKind             = "AttestationRequest"
	AttestationRequestCRDApiVersion       = AttestationRequestCRDGroup + "/" + AttestationRequestCRDVersion
)

const (
	AgentServicePort int32 = 9090
)

const (
	ControlPlaneLabel = "node-role.kubernetes.io/control-plane"
)

func NewAgent(agentName string) *Agent {
	return &Agent{
		TypeMeta: metav1.TypeMeta{
			APIVersion: AgentCRDApiVersion,
			Kind:       AgentCRDKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: agentName,
		},
		Spec: AgentSpec{
			AgentName:  agentName,
			NodeStatus: model.TrustedNodeStatus,
			PodStatus:  make([]PodStatus, 0),
			LastUpdate: time.Now(),
		},
	}
}

func (a *Agent) CheckPodExists(podName, tenantId string) bool {
	for _, pod := range a.Spec.PodStatus {
		if pod.PodName == podName && pod.TenantId == tenantId {
			return true
		}
	}
	return false
}

func (a *Agent) GetPodStatus(podName, tenantId string) *PodStatus {
	for _, pod := range a.Spec.PodStatus {
		if pod.PodName == podName && pod.TenantId == tenantId {
			return &pod
		}
	}
	return nil
}

func (a *Agent) GetNodeStatus() model.NodeStatusType {
	return a.Spec.NodeStatus
}

func (a *Agent) IsNodeTrusted() bool {
	return a.Spec.NodeStatus == model.TrustedNodeStatus
}

func (a *Agent) AllPodTrusted() bool {
	for _, pod := range a.Spec.PodStatus {
		if pod.Status != model.TrustedPodStatus {
			return false
		}
	}
	return true
}

func (a *Agent) IsPodTrusted(podName, tenantId string) (bool, error) {
	for _, pod := range a.Spec.PodStatus {
		if pod.PodName == podName && pod.TenantId == tenantId {
			return pod.Status == model.TrustedPodStatus, nil
		}
	}
	return false, fmt.Errorf("pod '%s' not found", podName)
}

func (a *Agent) AddPodStatus(podStatus PodStatus) {
	if a.Spec.PodStatus == nil {
		a.Spec.PodStatus = make([]PodStatus, 0)
	}
	a.Spec.PodStatus = append(a.Spec.PodStatus, podStatus)
	a.Spec.LastUpdate = time.Now()
}

func (a *Agent) UpdateNodeStatus(status model.NodeStatusType) {
	a.Spec.NodeStatus = status
	a.Spec.LastUpdate = time.Now()
}

func (a *Agent) UpdatePodStatus(podName, tenantId string, status model.PodStatusType, reason string) error {
	if a.Spec.PodStatus == nil {
		return fmt.Errorf("podStatus is empty")
	}

	for i, pod := range a.Spec.PodStatus {
		if pod.PodName == podName && pod.TenantId == tenantId {
			now := time.Now()
			a.Spec.PodStatus[i].Status = status
			a.Spec.PodStatus[i].Reason = reason
			a.Spec.PodStatus[i].LastCheck = now
			a.Spec.LastUpdate = now
			return nil
		}
	}
	return fmt.Errorf("pod '%s' not found", podName)
}

func (a *Agent) RemovePodStatus(podName, tenantId string) error {
	if a.Spec.PodStatus == nil {
		return fmt.Errorf("podStatus is empty")
	}
	for i, pod := range a.Spec.PodStatus {
		if pod.PodName == podName && pod.TenantId == tenantId {
			a.Spec.PodStatus = append(a.Spec.PodStatus[:i], a.Spec.PodStatus[i+1:]...)
			a.Spec.LastUpdate = time.Now()
			return nil
		}
	}
	return fmt.Errorf("pod '%s' not found", podName)
}

func (a *Agent) IsPodTracked(podName, tenantId string) bool {
	for _, pod := range a.Spec.PodStatus {
		if pod.PodName == podName && pod.TenantId == tenantId {
			return true
		}
	}
	return false
}

func (ar *AttestationRequest) ToUnstructured() (*unstructured.Unstructured, error) {
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(ar)
	if err != nil {
		return nil, fmt.Errorf("failed to convert AttestationRequest to unstructured: %v", err)
	}
	return &unstructured.Unstructured{
		Object: unstructuredObj,
	}, nil
}

func (ar *AttestationRequest) FromUnstructured(unstructuredObj *unstructured.Unstructured) error {
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, ar); err != nil {
		return fmt.Errorf("failed to convert unstructured to AttestationRequest: %v", err)
	}
	return nil
}

func NewAttestationRequest(podName, podUid, tenantId, agentName, agentIP string) *AttestationRequest {
	attestationRequestName := fmt.Sprintf("attestation-request-%s", podName)
	return &AttestationRequest{
		TypeMeta: metav1.TypeMeta{
			APIVersion: AttestationRequestCRDApiVersion,
			Kind:       AttestationRequestCRDKind,
		},
		ObjectMeta: metav1.ObjectMeta{
			Name: attestationRequestName,
		},
		Spec: AttestationRequestSpec{
			PodName:   podName,
			PodUid:    podUid,
			TenantId:  tenantId,
			AgentName: agentName,
			AgentIP:   agentIP,
			Issued:    time.Now(),
			HMAC:      nil, // to be computed later
		},
	}
}

func (ar *AttestationRequest) ComputeHMAC(key []byte) {
	integrityMessage := []byte(fmt.Sprintf("%s::%s::%s::%s::%s", ar.Spec.PodName, ar.Spec.PodUid, ar.Spec.TenantId, ar.Spec.AgentName, ar.Spec.AgentIP))
	ar.Spec.HMAC = cryptoUtils.ComputeHMAC(integrityMessage, key)
}

func (ar *AttestationRequest) ValidateHMAC(key []byte) (bool, error) {
	if ar.Spec.HMAC == nil || len(ar.Spec.HMAC) == 0 {
		return false, fmt.Errorf("missing HMAC in Attestation request")
	}
	integrityMessage := []byte(fmt.Sprintf("%s::%s::%s::%s::%s", ar.Spec.PodName, ar.Spec.PodUid, ar.Spec.TenantId, ar.Spec.AgentName, ar.Spec.AgentIP))
	err := cryptoUtils.VerifyHMAC(integrityMessage, key, ar.Spec.HMAC)
	if err != nil {
		return false, fmt.Errorf("failed to validate Attestation request HMAC: %v", err)
	}
	return true, nil
}

func (a *Agent) ToUnstructured() (*unstructured.Unstructured, error) {
	unstructuredObj, err := runtime.DefaultUnstructuredConverter.ToUnstructured(a)
	if err != nil {
		return nil, fmt.Errorf("failed to convert Agent to unstructured: %v", err)
	}
	return &unstructured.Unstructured{
		Object: unstructuredObj,
	}, nil
}

func (a *Agent) FromUnstructured(unstructuredObj *unstructured.Unstructured) error {
	if err := runtime.DefaultUnstructuredConverter.FromUnstructured(unstructuredObj.Object, a); err != nil {
		return fmt.Errorf("failed to convert unstructured to Agent: %v", err)
	}
	return nil
}

func (c *ClusterInteraction) DeleteAttestationRequestCRDInstance(crdObj interface{}) (bool, error) {
	// Assert that crdObj is of type *unstructured.Unstructured
	unstructuredObj, ok := crdObj.(*unstructured.Unstructured)
	if !ok {
		return false, fmt.Errorf("invalid AttestationRequest CRD object")
	}

	resourceName := unstructuredObj.GetName()

	// Delete the AttestationRequest CR in the given namespace
	err := c.DynamicClient.Resource(AttestationRequestGVR).Namespace(PodAttestationNamespace).Delete(context.TODO(), resourceName, metav1.DeleteOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to delete attestation request CRD: %v", err)
	}
	return true, nil
}

// GetPodImageDataByUid retrieves the image and its digest of a pod given its UID
func (c *ClusterInteraction) GetPodImageDataByUid(podUid string) (string, string, error) {
	// List all pods in the cluster (you may want to filter by namespace in production)
	pods, err := c.ClientSet.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return "", "", fmt.Errorf("failed to list pods: %v", err)
	}

	// Iterate over the pods to find the one with the matching UID
	for _, pod := range pods.Items {
		if string(pod.UID) == podUid {
			// If pod found, return the image and its digest (if available)
			if len(pod.Spec.Containers) > 0 {
				imageName := pod.Spec.Containers[0].Image
				imageDigest := ""
				// Check if image digest is available
				for _, status := range pod.Status.ContainerStatuses {
					if status.Name == pod.Spec.Containers[0].Name && status.ImageID != "" {
						imageDigest = status.ImageID
						return imageName, imageDigest, nil
					}
				}
				return "", "", fmt.Errorf("no image digest found in pod with uid: '%s'", podUid)
			}
			return "", "", fmt.Errorf("no containers found in pod with UID: '%s'", podUid)
		}
	}
	// If no pod is found with the given UID
	return "", "", fmt.Errorf("no pod found with UID: '%s'", podUid)
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
	c.ApiExtensionsClient, err = apiextensionsv1clientset.NewForConfig(config)
	if err != nil {
		logger.Fatal("Failed to create Kubernetes API extension client: %v", err)
	}
	c.MetricsClient, err = metricsclient.NewForConfig(config)
	if err != nil {
		logger.Fatal("Failed to create Kubernetes metrics client: %v", err)
	}
}

func (c *ClusterInteraction) ChooseBestWorkerNode() (*v1.Node, error) {
	nodes, err := c.ClientSet.CoreV1().Nodes().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes: %v", err)
	}

	nodeMetrics, err := c.MetricsClient.MetricsV1beta1().NodeMetricses().List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to list nodes metrics: %v", err)
	}

	usageMap := make(map[string]v1.ResourceList)
	for _, m := range nodeMetrics.Items {
		usageMap[m.GetName()] = v1.ResourceList{
			v1.ResourceCPU:    *resource.NewQuantity(m.Usage.Cpu().MilliValue(), resource.DecimalSI),
			v1.ResourceMemory: *resource.NewQuantity(m.Usage.Memory().MilliValue(), resource.BinarySI),
		}
	}

	var bestNode *v1.Node
	bestScore := math.MaxFloat64

	for _, node := range nodes.Items {
		alloc := node.Status.Allocatable
		used := usageMap[node.GetName()]

		cpuRatio := float64(used.Cpu().MilliValue()) / float64(alloc.Cpu().MilliValue())
		memRatio := float64(used.Memory().MilliValue()) / float64(alloc.Memory().MilliValue())

		score := 0.7*cpuRatio + 0.3*memRatio
		if score < bestScore {
			bestScore = score
			bestNode = &node
		}
	}
	return bestNode, nil
}

func (c *ClusterInteraction) CreateTenantPodFromManifest(podManifest []byte, tenantId string) (*v1.Pod, error) {
	var pod *v1.Pod

	if err := yaml.Unmarshal(podManifest, &pod); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	if pod.Kind != "Pod" {
		return nil, fmt.Errorf("provided manifest is not a Deployment")
	}

	if pod.Annotations == nil {
		pod.Annotations = make(map[string]string)
	}
	pod.Annotations["tenantId"] = tenantId

	createdPod, err := c.ClientSet.CoreV1().Pods(pod.GetNamespace()).Create(context.TODO(), pod, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create Pod: %v", err)
	}
	return createdPod, nil
}

func (c *ClusterInteraction) CreateTenantDeploymentFromManifest(deploymentManifest []byte, tenantId string) (*appsv1.Deployment, error) {
	var deployment *appsv1.Deployment

	if err := yaml.Unmarshal(deploymentManifest, &deployment); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	if deployment.Kind != "Deployment" {
		return nil, fmt.Errorf("provided manifest is not a Deployment")
	}

	if deployment.Annotations == nil {
		deployment.Annotations = make(map[string]string)
	}

	deployment.Annotations["tenantId"] = tenantId

	createdDeployment, err := c.ClientSet.AppsV1().Deployments(deployment.GetNamespace()).Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create Deployment: %v", err)
	}
	return createdDeployment, nil
}

func (c *ClusterInteraction) CreateTenantReplicaSetFromManifest(replicaSetManifest []byte, tenantId string) (*appsv1.ReplicaSet, error) {
	var replicaSet *appsv1.ReplicaSet

	if err := yaml.Unmarshal(replicaSetManifest, &replicaSet); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	if replicaSet.Kind != "ReplicaSet" {
		return nil, fmt.Errorf("provided manifest is not a Replicaset")
	}

	if replicaSet.Annotations == nil {
		replicaSet.Annotations = make(map[string]string)
	}

	replicaSet.Annotations["tenantId"] = tenantId

	createdReplicaSet, err := c.ClientSet.AppsV1().ReplicaSets(replicaSet.GetNamespace()).Create(context.TODO(), replicaSet, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create ReplicaSet: %v", err)
	}

	return createdReplicaSet, nil
}

func (c *ClusterInteraction) CreateTenantStatefulSetFromManifest(statefulSetManifest []byte, tenantId string) (*appsv1.StatefulSet, error) {
	var statefulSet *appsv1.StatefulSet

	if err := yaml.Unmarshal(statefulSetManifest, &statefulSet); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	if statefulSet.Kind != "StatefulSet" {
		return nil, fmt.Errorf("provided manifest is not a StatefulSet")
	}

	if statefulSet.Annotations == nil {
		statefulSet.Annotations = make(map[string]string)
	}

	statefulSet.Annotations["tenantId"] = tenantId

	createdStatefulSet, err := c.ClientSet.AppsV1().StatefulSets(statefulSet.GetNamespace()).Create(context.TODO(), statefulSet, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create ReplicaSet: %v", err)
	}
	return createdStatefulSet, nil
}

func (c *ClusterInteraction) CreateTenantDaemonSetFromManifest(daemonSetManifest []byte, tenantId string) (*appsv1.DaemonSet, error) {
	var daemonSet *appsv1.DaemonSet

	if err := yaml.Unmarshal(daemonSetManifest, &daemonSet); err != nil {
		return nil, fmt.Errorf("failed to unmarshal YAML: %v", err)
	}

	if daemonSet.Kind != "DaemonSet" {
		return nil, fmt.Errorf("provided manifest is not a DaemonSet")
	}

	if daemonSet.Annotations == nil {
		daemonSet.Annotations = make(map[string]string)
	}

	daemonSet.Annotations["tenantId"] = tenantId

	createdDaemonSet, err := c.ClientSet.AppsV1().DaemonSets(daemonSet.GetNamespace()).Create(context.TODO(), daemonSet, metav1.CreateOptions{})
	if err != nil {
		return nil, fmt.Errorf("failed to create ReplicaSet: %v", err)
	}
	return createdDaemonSet, nil
}

func (c *ClusterInteraction) DeleteAgentCRDInstance(nodeName string) error {
	// Construct the name of the Agent CRD based on the node name
	agentCRDName := fmt.Sprintf("agent-%s", nodeName)

	// Delete the Agent CRD instance in the "kube-system" namespace
	err := c.DynamicClient.Resource(AgentGVR).Namespace(PodAttestationNamespace).Delete(context.TODO(), agentCRDName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("error deleting Agent CRD instance: %v\n", err)

	}
	return nil
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
		err := c.ClientSet.CoreV1().Pods(pod.GetNamespace()).Delete(context.TODO(), pod.GetName(), metav1.DeleteOptions{})
		if err != nil {
			return false, fmt.Errorf("error deleting pod '%s': %v", pod.GetName(), err)
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
		err := c.ClientSet.CoreV1().Pods(pod.GetNamespace()).Delete(context.TODO(), pod.GetName(), metav1.DeleteOptions{})
		if err != nil {
			return false, fmt.Errorf("error deleting pod '%s' from node '%s': %v", pod.GetName(), nodeName, err)
		}
		logger.Success("Deleted pod '%s' from node '%s'", pod.GetName(), nodeName)
	}
	return true, nil
}

// GetAgentPort returns the NodePort for a given service in a namespace
func (c *ClusterInteraction) GetAgentPort(agentName string) (int32, error) {
	agentServiceName := fmt.Sprintf("%s-service", agentName)

	// Get the Service from the given namespace
	service, err := c.ClientSet.CoreV1().Services(PodAttestationNamespace).Get(context.TODO(), agentServiceName, metav1.GetOptions{})
	if err != nil {
		return -1, fmt.Errorf("failed to get service: %v", err)
	}

	// Iterate through the service ports to find a NodePort
	for _, port := range service.Spec.Ports {
		if port.NodePort != 0 {
			return port.NodePort, nil
		}
	}

	return -1, fmt.Errorf("no NodePort found for service %s", agentServiceName)
}

func (c *ClusterInteraction) CreateAndIssueAttestationRequestCRD(podName, podUid, tenantId, agentName, agentIP string, hmacKey []byte) (bool, error) {
	attestationRequest := NewAttestationRequest(podName, podUid, tenantId, agentName, agentIP)
	attestationRequest.ComputeHMAC(hmacKey)

	// Convert to unstructured
	unstructuredObj, err := attestationRequest.ToUnstructured()
	if err != nil {
		return false, fmt.Errorf("failed to convert attestation request to unstructured: %v", err)
	}

	// Create the CR
	if _, err = c.DynamicClient.Resource(AttestationRequestGVR).Namespace(PodAttestationNamespace).Create(context.TODO(), unstructuredObj, metav1.CreateOptions{}); err != nil {
		return false, fmt.Errorf("failed to create attestation request: %v", err)
	}

	return true, nil
}

func (c *ClusterInteraction) IssueAttestationRequestCRD(attestationRequest *AttestationRequest) (bool, error) {
	// Convert to unstructured
	unstructuredObj, err := attestationRequest.ToUnstructured()
	if err != nil {
		return false, fmt.Errorf("failed to convert attestation request to unstructured: %v", err)
	}

	// Create the CR
	if _, err = c.DynamicClient.Resource(AttestationRequestGVR).Namespace(PodAttestationNamespace).Create(context.TODO(), unstructuredObj, metav1.CreateOptions{}); err != nil {
		return false, fmt.Errorf("failed to create attestation request: %v", err)
	}

	return true, nil
}

func (c *ClusterInteraction) CheckAgentStatus(nodeName string) (bool, error) {
	agentName := fmt.Sprintf("agent-%s", nodeName)
	// Use the dynamic client to get the CRD by name
	unstructuredObj, err := c.DynamicClient.Resource(AgentGVR).Namespace(PodAttestationNamespace).Get(context.TODO(), agentName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to retrieve Agent CRD: %v", err)
	}

	var agent Agent
	if err = agent.FromUnstructured(unstructuredObj); err != nil {
		return false, fmt.Errorf("error converting Agent CRD to structured type: %v", err)
	}

	if !agent.IsNodeTrusted() {
		return false, fmt.Errorf("node '%s' is not trusted", nodeName)
	}

	if !agent.AllPodTrusted() {
		return false, fmt.Errorf("not all pods on node '%s' are trusted", nodeName)
	}

	return true, nil
}

func (c *ClusterInteraction) CheckPodStatus(nodeName, podName, tenantId string) (bool, error) {
	agentName := fmt.Sprintf("agent-%s", nodeName)
	// Use the dynamic client to get the CRD by name
	unstructuredObj, err := c.DynamicClient.Resource(AgentGVR).Namespace(PodAttestationNamespace).Get(context.TODO(), agentName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to retrieve Agent CRD: %v", err)
	}

	var agent Agent
	if err = agent.FromUnstructured(unstructuredObj); err != nil {
		return false, fmt.Errorf("error converting Agent CRD to structured type: %v", err)
	}

	if !agent.IsNodeTrusted() {
		return false, fmt.Errorf("node '%s' is not trusted", nodeName)
	}

	isPodTrusted, err := agent.IsPodTrusted(podName, tenantId)
	if err != nil {
		return false, fmt.Errorf("failed to retrieve requested pod '%s' in the Agent CRD '%s'", podName, agentName)
	}
	return isPodTrusted, nil
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
		if pod.GetName() == podName {
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

func (c *ClusterInteraction) DeleteAgent(workerName string) error {
	deploymentName := fmt.Sprintf("agent-%s-deployment", workerName)
	serviceName := fmt.Sprintf("agent-%s-service", workerName)

	// Delete the Service
	err := c.ClientSet.CoreV1().Services(PodAttestationNamespace).Delete(context.TODO(), serviceName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete Agent service '%s': %v", serviceName, err)
	}

	// Delete the Deployment
	err = c.ClientSet.AppsV1().Deployments(PodAttestationNamespace).Delete(context.TODO(), deploymentName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete Agent deplooyment '%s': %v", deploymentName, err)
	}
	return nil
}

func (c *ClusterInteraction) DeployAgent(newWorker *v1.Node, agentConfig *model.AgentConfig) (bool, string, string, int, error) {
	agentReplicas := int32(1)
	privileged := true
	charDeviceType := v1.HostPathCharDev
	pathFileType := v1.HostPathFile
	agentDeploymentName := fmt.Sprintf("agent-%s-deployment", newWorker.GetName())
	agentContainerName := fmt.Sprintf("agent-%s", newWorker.GetName())
	agentServiceName := fmt.Sprintf("agent-%s-service", newWorker.GetName())

	agentHost, err := c.GetWorkerInternalIP(newWorker)
	if err != nil {
		return false, "", "", -1, fmt.Errorf("failed to get node '%s' internal IP address: %v", newWorker.GetName(), err)
	}

	agentNodePort := agentConfig.AgentNodePortAllocation

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
							Image: agentConfig.ImageName,
							Env: []v1.EnvVar{
								{Name: "AGENT_PORT", Value: strconv.Itoa(int(agentConfig.AgentPort))},
								{Name: "TPM_PATH", Value: agentConfig.TPMPath},
							},
							Ports: []v1.ContainerPort{
								{ContainerPort: agentConfig.AgentPort},
							},
							VolumeMounts: []v1.VolumeMount{
								{Name: "tpm-device", MountPath: agentConfig.TPMPath},
								{Name: "ima-measurements", MountPath: agentConfig.IMAMountPath, ReadOnly: true},
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
									Path: agentConfig.TPMPath,
									Type: &charDeviceType,
								},
							},
						},
						{
							Name: "ima-measurements",
							VolumeSource: v1.VolumeSource{
								HostPath: &v1.HostPathVolumeSource{
									Path: agentConfig.IMAMeasurementLogPath,
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
	agentDeployment, err = c.ClientSet.AppsV1().Deployments(PodAttestationNamespace).Create(context.TODO(), agentDeployment, metav1.CreateOptions{})
	if err != nil {
		return false, "", "", -1, fmt.Errorf("error creating agent deployment '%s': %v", agentDeploymentName, err)
	}

	// Deploy the Service
	_, err = c.ClientSet.CoreV1().Services(PodAttestationNamespace).Create(context.TODO(), agentService, metav1.CreateOptions{})
	if err != nil {
		delErr := c.ClientSet.AppsV1().Deployments(PodAttestationNamespace).Delete(context.TODO(), agentDeployment.GetName(), metav1.DeleteOptions{})
		if delErr != nil {
			return false, "", "", -1, fmt.Errorf("error creating agent service '%s': %v; error deleting agent deployment '%s': %v", agentService.Name, err, agentDeployment.Name, delErr)
		}
		return false, "", "", -1, fmt.Errorf("error creating agent service '%s': %v", agentService.GetName(), err)
	}

	agentConfig.AgentNodePortAllocation += 1
	return true, agentDeployment.GetName(), agentHost, int(agentNodePort), nil
}

// WaitForAllDeploymentPodsRunning  waits for the given pod to reach the "Running" state
func (c *ClusterInteraction) WaitForAllDeploymentPodsRunning(namespace, deploymentName string, timeout time.Duration) error {
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Get deployment to extract label selector
	deployment, err := c.ClientSet.AppsV1().Deployments(namespace).Get(ctx, deploymentName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("failed to get deployment '%s': %v", deploymentName, err)
	}

	// Use deployment's label selector to find matching pods
	labelSelector := metav1.FormatLabelSelector(deployment.Spec.Selector)

	watcher, err := c.ClientSet.CoreV1().Pods(namespace).Watch(ctx, metav1.ListOptions{
		LabelSelector: labelSelector,
	})
	if err != nil {
		return fmt.Errorf("failed to watch pods for deployment '%s': %v", deploymentName, err)
	}
	defer watcher.Stop()

	// Keep track of running pods
	runningPods := make(map[string]bool)

	for {
		select {
		case <-ctx.Done():
			return fmt.Errorf("timed out waiting for all pods of deployment '%s' to be running", deploymentName)
		case event, ok := <-watcher.ResultChan():
			if !ok {
				return fmt.Errorf("watcher closed unexpectedly for deployment '%s'", deploymentName)
			}

			pod, ok := event.Object.(*v1.Pod)
			if !ok {
				return fmt.Errorf("unexpected type while watching pod")
			}

			// Update running pods tracking
			if pod.Status.Phase == v1.PodRunning {
				runningPods[pod.GetName()] = true
			} else {
				delete(runningPods, pod.GetName()) // Remove from running list if not in Running phase
			}

			// Get the latest pod list to check the total number of pods
			pods, err := c.ClientSet.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{
				LabelSelector: labelSelector,
			})
			if err != nil {
				return fmt.Errorf("failed to list pods for deployment '%s': %v", deploymentName, err)
			}

			// Check if all pods are in the running state
			if len(runningPods) == len(pods.Items) {
				return nil
			}
		}
	}
}

func (c *ClusterInteraction) CreateAgentCRDInstance(nodeName string) (bool, error) {
	nodeFieldSelector := fmt.Sprintf("spec.nodeName=%s", nodeName)
	// Get the list of pods running on the specified node and attestation namespace
	pods, err := c.ClientSet.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: nodeFieldSelector,
	})
	if err != nil {
		return false, fmt.Errorf("error getting pods of Worker node '%s': %v", nodeName, err)
	}

	agentName := fmt.Sprintf("agent-%s", nodeName)
	newAgent := NewAgent(agentName)

	for _, pod := range pods.Items {
		// do not add pods that are not deployed within a namespace enabled for attestation
		if c.IsNamespaceEnabledForAttestation(pod.GetNamespace()) {
			continue
		}

		podName := pod.GetName()
		tenantId := pod.Annotations["tenantId"]

		isWorkload := pod.GetNamespace() != PodAttestationNamespace && pod.GetNamespace() != KubeSystemNamespace

		if !isWorkload {
			continue
		}

		newAgent.AddPodStatus(PodStatus{
			PodName:   podName,
			TenantId:  tenantId,
			Status:    model.NewPodStatus,
			Reason:    "Agent just created",
			LastCheck: time.Now(),
		})
	}

	unstructuredAgent, err := newAgent.ToUnstructured()
	if err != nil {
		return false, fmt.Errorf("error converting Agent CRD instance '%s' to unstructured: %v", agentName, err)
	}
	// Create the Agent CRD instance in the kube-system namespace
	_, err = c.DynamicClient.Resource(AgentGVR).Namespace(PodAttestationNamespace).Create(context.TODO(), unstructuredAgent, metav1.CreateOptions{})
	if err != nil {
		return false, fmt.Errorf("error creating Agent CRD instance '%s': %v", agentName, err)
	}
	return true, nil
}

func (c *ClusterInteraction) DeleteAttestationRequestCRD() error {
	// Delete the CRD
	err := c.ApiExtensionsClient.ApiextensionsV1().CustomResourceDefinitions().Delete(context.TODO(), AttestationRequestCRDName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete Attestation Request CRD: %v", err)
	}
	return nil
}

func (c *ClusterInteraction) DeleteAgentCRD() error {
	// Delete the CRD
	err := c.ApiExtensionsClient.ApiextensionsV1().CustomResourceDefinitions().Delete(context.TODO(), AgentCRDName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("failed to delete Agent CRD: %v", err)
	}
	return nil
}

func (c *ClusterInteraction) DefineAgentCRD() error {
	// Define the CustomResourceDefinition
	agentCRD := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: AgentCRDName,
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: AgentCRDGroup,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     AgentCRDKind,
				ListKind: AgentCRDListKind,
				Plural:   AgentCRDResourcePlural,
				Singular: AgentCRDResourceSingular,
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    AgentCRDVersion,
					Served:  true,
					Storage: true,
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]apiextensionsv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]apiextensionsv1.JSONSchemaProps{
										"agentName": {
											Type: "string",
										},
										"nodeStatus": {
											Type: "string",
										},
										"podStatus": {
											Type: "array",
											Items: &apiextensionsv1.JSONSchemaPropsOrArray{
												Schema: &apiextensionsv1.JSONSchemaProps{
													Type: "object",
													Properties: map[string]apiextensionsv1.JSONSchemaProps{
														"podName": {
															Type: "string",
														},
														"tenantId": {
															Type: "string",
														},
														"status": {
															Type: "string",
														},
														"reason": {
															Type: "string",
														},
														"lastCheck": {
															Type:   "string",
															Format: "date-time",
														},
													},
												},
											},
										},
										"lastUpdate": {
											Type:   "string",
											Format: "date-time",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Create the CRD
	agentCRD, err := c.ApiExtensionsClient.ApiextensionsV1().CustomResourceDefinitions().Create(context.TODO(), agentCRD, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to define Agent CRD: %v", err)
	}
	return nil
}

func (c *ClusterInteraction) DefineAttestationRequestCRD() error {
	// Define the CustomResourceDefinition
	attestationRequestCRD := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: AttestationRequestCRDName,
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: AttestationRequestCRDGroup,
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     AttestationRequestCRDKind,
				ListKind: AttestationRequestCRDListKind,
				Plural:   AttestationRequestCRDResourcePlural,
				Singular: AttestationRequestCRDResourceSingular,
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    AttestationRequestCRDVersion,
					Served:  true,
					Storage: true,
					Schema: &apiextensionsv1.CustomResourceValidation{
						OpenAPIV3Schema: &apiextensionsv1.JSONSchemaProps{
							Type: "object",
							Properties: map[string]apiextensionsv1.JSONSchemaProps{
								"spec": {
									Type: "object",
									Properties: map[string]apiextensionsv1.JSONSchemaProps{
										"podName": {
											Type: "string",
										},
										"podUid": {
											Type: "string",
										},
										"tenantId": {
											Type: "string",
										},
										"agentName": {
											Type: "string",
										},
										"agentIP": {
											Type: "string",
										},
										"issued": {
											Type:   "string",
											Format: "date-time",
										},
										"hmac": {
											Type: "string",
										},
									},
								},
							},
						},
					},
				},
			},
		},
	}

	// Create the CRD
	attestationRequestCRD, err := c.ApiExtensionsClient.ApiextensionsV1().CustomResourceDefinitions().Create(context.TODO(), attestationRequestCRD, metav1.CreateOptions{})
	if err != nil {
		return fmt.Errorf("failed to define Attestation Request CRD: %v", err)
	}
	return nil
}

func (c *ClusterInteraction) IsPodTracked(nodeName, podName, tenantId string) (bool, error) {
	if nodeName == "" {
		pod, err := c.ClientSet.CoreV1().Pods("").Get(context.TODO(), podName, metav1.GetOptions{})
		if err != nil {
			return false, fmt.Errorf("failed to retrieve node from pod '%s': %v", podName, err)
		}
		nodeName = pod.Spec.NodeName
		if nodeName == "" {
			return false, fmt.Errorf("pod '%s' is not scheduled on any node", podName)
		}

		if tenantId != pod.Annotations["tenantId"] {
			return false, fmt.Errorf("tenant ID mismatch for pod '%s'", podName)
		}
	}

	agentName := "agent-" + nodeName
	agentResource := c.DynamicClient.Resource(AgentGVR).Namespace(PodAttestationNamespace)
	unstructuredObj, err := agentResource.Get(context.Background(), agentName, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("error getting Agent CRD instance: %v", err)
	}

	var agent Agent
	if err = agent.FromUnstructured(unstructuredObj); err != nil {
		return false, fmt.Errorf("error converting Agent CRD to structured type: %v", err)
	}

	isPodTracked := agent.IsPodTracked(podName, tenantId)
	return isPodTracked, nil
}

func (c *ClusterInteraction) GetPodStatus(nodeName, podName, tenantId string) (*PodStatus, error) {
	agentCRDName := "agent-" + nodeName
	agentResource := c.DynamicClient.Resource(AgentGVR).Namespace(PodAttestationNamespace)

	unstructuredObj, err := agentResource.Get(context.Background(), agentCRDName, metav1.GetOptions{})
	if err != nil {
		return nil, fmt.Errorf("error getting Agent CRD instance: %v", err)
	}

	var agent Agent
	if err = agent.FromUnstructured(unstructuredObj); err != nil {
		return nil, fmt.Errorf("error converting Agent CRD to structured type: %v", err)
	}
	podStatus := agent.GetPodStatus(podName, tenantId)
	return podStatus, nil
}

func (c *ClusterInteraction) UpdatePodStatus(nodeName, podName, tenantId, reason string, status model.PodStatusType) error {
	agentCRDName := "agent-" + nodeName
	agentResource := c.DynamicClient.Resource(AgentGVR).Namespace(PodAttestationNamespace)

	unstructuredObj, err := agentResource.Get(context.Background(), agentCRDName, metav1.GetOptions{})
	if err != nil {
		return fmt.Errorf("error getting Agent CRD instance: %v", err)
	}

	var agent Agent
	if err = agent.FromUnstructured(unstructuredObj); err != nil {
		return fmt.Errorf("error converting Agent CRD to structured type: %v", err)
	}

	if !status.IsValidPodStatus() {
		return fmt.Errorf("invalid pod status type: %s", status)
	}

	switch status {
	case model.NewPodStatus:
		agent.AddPodStatus(PodStatus{
			PodName:   podName,
			TenantId:  tenantId,
			Status:    status,
			Reason:    reason,
			LastCheck: time.Now(),
		})
		break

	case model.DeletedPodStatus:
		err = agent.RemovePodStatus(podName, tenantId)
		if err != nil {
			return fmt.Errorf("pod '%s' for tenant '%s' not found in Agent CRD", podName, tenantId)
		}
		break

	// TRUSTED, UNTRUSTED, UNKNOWN
	default:
		err = agent.UpdatePodStatus(podName, tenantId, status, reason)
		if err != nil {
			return fmt.Errorf("pod '%s' for tenant '%s' not found in Agent CRD", podName, tenantId)
		}
		break
	}

	unstructuredAgent, err := agent.ToUnstructured()
	if err != nil {
		return fmt.Errorf("error converting Agent CRD back to unstructured: %v", err)
	}

	if _, err = agentResource.Update(context.Background(), unstructuredAgent, metav1.UpdateOptions{}); err != nil {
		return fmt.Errorf("error updating Agent CRD '%s': %v", agentCRDName, err)
	}
	return nil
}

func (c *ClusterInteraction) UpdateAgentCRDWithAttestationResult(attestationResult *model.AttestationResult) (bool, error) {
	// Get the dynamic client resource interface for the CRD
	agentResource := c.DynamicClient.Resource(AgentGVR).Namespace(PodAttestationNamespace) // Modify namespace if needed

	// Fetch the CRD instance for the given node
	unstructuredObj, err := agentResource.Get(context.Background(), attestationResult.Agent, metav1.GetOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to get Agent CRD: '%s'", attestationResult.Agent)
	}

	var agent Agent
	err = agent.FromUnstructured(unstructuredObj)
	if err != nil {
		return false, fmt.Errorf("error converting Agent CRD to structured type: %v", err)
	}

	switch attestationResult.Result.GetKind() {
	case model.NodeTarget:
		nodeResult := attestationResult.Result.(model.NodeResult)
		agent.UpdateNodeStatus(nodeResult.Result)
		break

	case model.PodTarget:
		podResult := attestationResult.Result.(model.PodResult)
		err = agent.UpdatePodStatus(podResult.Name, podResult.TenantId, podResult.Result, podResult.Reason)
		if err != nil {
			return false, fmt.Errorf("pod '%s' for tenant '%s' not found in Agent CRD", podResult.Name, podResult.TenantId)
		}
		break
	}

	unstructuredAgent, err := agent.ToUnstructured()
	if err != nil {
		return false, fmt.Errorf("error converting Agent CRD back to unstructured: %v", err)
	}

	_, err = agentResource.Update(context.Background(), unstructuredAgent, metav1.UpdateOptions{})
	if err != nil {
		return false, fmt.Errorf("failed to update Agent CRD '%s'", attestationResult.Agent)
	}
	return true, nil
}
