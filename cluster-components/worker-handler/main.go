package main

import (
	"bytes"
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/fatih/color"
	"io"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	v1 "k8s.io/api/core/v1"
	apiextensionsv1 "k8s.io/apiextensions-apiserver/pkg/apis/apiextensions/v1"
	apiextensionsv1clientset "k8s.io/apiextensions-apiserver/pkg/client/clientset/clientset"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/apimachinery/pkg/util/intstr"
	"k8s.io/client-go/informers"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/util/homedir"
	"log"
	"net"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"

	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/tpm_attestation"
)

// Color variables for output
var (
	red                          *color.Color
	green                        *color.Color
	yellow                       *color.Color
	clientset                    *kubernetes.Clientset
	dynamicClient                dynamic.Interface
	apiExtensionsClient          *apiextensionsv1clientset.Clientset
	attestationNamespaces        string
	attestationEnabledNamespaces []string
	registrarPORT                string
	registrarHOST                string
	whitelistHOST                string
	whitelistPORT                string
	agentServicePortAllocation   int32 = 9090
	agentNodePortAllocation      int32 = 31000
	verifierPublicKey            string
	IMAMountPath                 string
	IMAMeasurementLogPath        string
	TPMPath                      string
)

const ephemeralKeySize = 32

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
	registrarHOST = getEnv("REGISTRAR_HOST", "localhost")
	registrarPORT = getEnv("REGISTRAR_PORT", "8080")
	attestationNamespaces = getEnv("ATTESTATION_NAMESPACES", "[\"default\"]")
	whitelistHOST = getEnv("WHITELIST_HOST", "localhost")
	whitelistPORT = getEnv("WHITELIST_PORT", "9090")
	verifierPublicKey = getEnv("VERIFIER_PUBLIC_KEY", "")
	IMAMountPath = getEnv("IMA_MOUNT_PATH", "/root/ascii_runtime_measurements")
	IMAMeasurementLogPath = getEnv("IMA_ML_PATH", "/sys/kernel/security/integrity/ima/ascii_runtime_measurements")
	TPMPath = getEnv("TPM_PATH", "/dev/tpm0")

	// setting namespaces allowed for attestation: only pods deployed within them can be attested
	err := json.Unmarshal([]byte(attestationNamespaces), &attestationEnabledNamespaces)
	if err != nil {
		log.Fatalf("Failed to parse 'ATTESTATION_NAMESPACES' content: %v", err)
	}
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		if key == "ATTESTATION_NAMESPACES" {
			fmt.Printf(yellow.Sprintf("[%s] '%s' environment variable missing: setting default value: ['default']\n", time.Now().Format("02-01-2006 15:04:05"), key))
		}
		return defaultValue
	}
	return value
}

// isNamespaceEnabledForAttestation checks if the given podNamespace is enabled for attestation.
func isNamespaceEnabledForAttestation(podNamespace string) bool {
	for _, ns := range attestationEnabledNamespaces {
		if ns == podNamespace {
			return true
		}
	}
	return false
}

func getWorkerInternalIP(newWorker *corev1.Node) (string, error) {
	// Loop through the addresses of the node to find the InternalIP (within the cluster)
	var workerIP string
	for _, address := range newWorker.Status.Addresses {
		if address.Type == v1.NodeInternalIP {
			workerIP = address.Address
			break
		}
	}
	if workerIP == "" {
		return "", fmt.Errorf("no internal IP found for Node: %s", newWorker.GetName())
	}
	return workerIP, nil
}

func deployAgent(newWorker *corev1.Node) (bool, string, string) {
	// config values
	agentReplicas := int32(1)
	privileged := true
	charDeviceType := corev1.HostPathCharDev
	pathFileType := corev1.HostPathFile

	agentHOST, err := getWorkerInternalIP(newWorker)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to deploy Agent on Worker Node '%s': Node has no internal IP\n", time.Now().Format("02-01-2006 15:04:05"), newWorker.GetName()))
		return false, "", ""
	}
	// allocating ports for this agent deployment
	agentPORT := agentNodePortAllocation
	servicePORT := agentServicePortAllocation

	// Define the Deployment
	deployment := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("agent-%s-deployment", newWorker.GetName()),
			Namespace: "attestation-system",
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &agentReplicas,
			Selector: &metav1.LabelSelector{
				MatchLabels: map[string]string{
					"app": "agent",
				},
			},
			Template: corev1.PodTemplateSpec{
				ObjectMeta: metav1.ObjectMeta{
					Labels: map[string]string{
						"app": "agent",
					},
				},
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{
						{
							Name:  fmt.Sprintf("agent-%s", newWorker.GetName()),
							Image: "franczar/k8s-attestation-agent:latest",
							Env: []corev1.EnvVar{
								{Name: "AGENT_PORT", Value: "8080"},
								{Name: "TPM_PATH", Value: TPMPath},
							},
							Ports: []corev1.ContainerPort{
								{ContainerPort: 8080},
							},
							VolumeMounts: []corev1.VolumeMount{
								{Name: "tpm-device", MountPath: TPMPath},
								{Name: "ima-measurements", MountPath: IMAMountPath, ReadOnly: true},
							},
							SecurityContext: &corev1.SecurityContext{
								Privileged: &privileged,
							},
						},
					},
					Volumes: []corev1.Volume{
						{
							Name: "tpm-device",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
									Path: TPMPath,
									Type: &charDeviceType,
								},
							},
						},
						{
							Name: "ima-measurements",
							VolumeSource: corev1.VolumeSource{
								HostPath: &corev1.HostPathVolumeSource{
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
	service := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      fmt.Sprintf("agent-%s-service", newWorker.GetName()),
			Namespace: "attestation-system",
		},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{
				"app": "agent",
			},
			Ports: []corev1.ServicePort{
				{
					Protocol:   corev1.ProtocolTCP,
					Port:       servicePORT,
					TargetPort: intstr.FromInt32(8080),
					NodePort:   agentPORT,
				},
			},
			Type: corev1.ServiceTypeNodePort,
		},
	}

	// Deploy the Deployment
	_, err = clientset.AppsV1().Deployments("attestation-system").Create(context.TODO(), deployment, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to create Agent deployment: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false, "", ""
	}

	// Deploy the Service
	_, err = clientset.CoreV1().Services("attestation-system").Create(context.TODO(), service, metav1.CreateOptions{})
	if err != nil {
		log.Fatalf("[%s] Failed to create Agent service: %v\n", time.Now().Format("02-01-2006 15:04:05"), err)
		return false, "", ""
	}

	fmt.Printf(green.Sprintf("[%s] Agent Deployment and Service successfully created\n", time.Now().Format("02-01-2006 15:04:05")))
	agentNodePortAllocation += 1
	agentServicePortAllocation += 1
	return true, agentHOST, fmt.Sprintf("%d", agentPORT)
}

// configureKubernetesClient initializes the Kubernetes client.
func configureKubernetesClient() {
	var err error
	config, err := rest.InClusterConfig()
	if err != nil {
		kubeconfig := filepath.Join(homedir.HomeDir(), ".kube", "config")
		config, err = clientcmd.BuildConfigFromFlags("", kubeconfig)
		if err != nil {
			panic(err)
		}
	}
	dynamicClient = dynamic.NewForConfigOrDie(config)
	clientset, err = kubernetes.NewForConfig(config)
	apiExtensionsClient, err = apiextensionsv1clientset.NewForConfig(config)

	if err != nil {
		panic(err)
	}
}

func handleNodeAdd(node *corev1.Node) {
	if !nodeIsControlPlane(node) && !nodeIsRegistered(node.Name) {
		fmt.Printf(green.Sprintf("[%s] Worker Node '%s' joined the cluster\n", time.Now().Format("02-01-2006 15:04:05"), node.Name))

		isAgentDeployed, agentHOST, agentPORT := deployAgent(node)
		if !isAgentDeployed || !createAgentCRDInstance(node.Name) || !workerRegistration(node, agentHOST, agentPORT) {
			err := deleteNodeFromCluster(node.Name)
			if err != nil {
				fmt.Printf(red.Sprintf("[%s] Failed to delete Worker Node '%s' from the cluster: %v\n", time.Now().Format("02-01-2006 15:04:05"), node.Name, err))
			}
		}
	}
}

func handleNodeDelete(node *corev1.Node) {
	if !nodeIsControlPlane(node) {
		fmt.Printf(yellow.Sprintf("[%s] Worker Node '%s' deleted from the cluster\n", time.Now().Format("02-01-2006 15:04:05"), node.Name))

		err := deleteAgent(node.Name)
		if err != nil {
			fmt.Printf(red.Sprintf("[%s] Failed to delete Agent deployed on Worker Node '%s': %v\n", time.Now().Format("02-01-2006 15:04:05"), node.Name, err))
		}

		err = deleteAgentCRDInstance(node.Name)
		if err != nil {
			fmt.Printf(red.Sprintf("[%s] Failed to delete Agent CRD instance 'agent-%s': %v\n", time.Now().Format("02-01-2006 15:04:05"), node.Name, err))
		}

		err = workerRemoval(node.Name)
		if err != nil {
			fmt.Printf(red.Sprintf("[%s] Failed to remove Worker '%s' from Registrar database: %v\n", time.Now().Format("02-01-2006 15:04:05"), node.Name, err))
		}
	}
}

func watchNodes(stopCh chan os.Signal) {
	// Create an informer factory
	factory := informers.NewSharedInformerFactory(clientset, 0)
	nodeInformer := factory.Core().V1().Nodes().Informer()

	// Add event handlers for Node events
	nodeInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}
			handleNodeAdd(node)
		},
		DeleteFunc: func(obj interface{}) {
			node, ok := obj.(*corev1.Node)
			if !ok {
				return
			}
			handleNodeDelete(node)
		},
	})

	// Convert `chan os.Signal` to `<-chan struct{}`
	stopStructCh := make(chan struct{})
	go func() {
		<-stopCh // Wait for signal
		close(stopStructCh)
	}()

	// Start the informer
	go nodeInformer.Run(stopStructCh)

	// Wait for the informer to sync
	if !cache.WaitForCacheSync(stopStructCh, nodeInformer.HasSynced) {
		fmt.Println("Timed out waiting for caches to sync")
		return
	}

	// Keep running until stopped
	<-stopStructCh
	fmt.Println("Stopping application...")
}

// deleteNode deletes the node from the Kubernetes cluster.
func deleteNodeFromCluster(nodeName string) error {
	err := clientset.CoreV1().Nodes().Delete(context.TODO(), nodeName, metav1.DeleteOptions{})
	return err
}

func deleteAgent(removedWorkerName string) error {
	// Define the names of the Deployment and Service based on the worker name
	deploymentName := fmt.Sprintf("agent-%s-deployment", removedWorkerName)
	serviceName := fmt.Sprintf("agent-%s-service", removedWorkerName)

	// Delete the Service
	err := clientset.CoreV1().Services("attestation-system").Delete(context.TODO(), serviceName, metav1.DeleteOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to delete Agent service: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return fmt.Errorf("Failed to delete Agent service: %v", err)
	}
	fmt.Printf(yellow.Sprintf("[%s] Agent Service '%s' successfully deleted\n", time.Now().Format("02-01-2006 15:04:05"), serviceName))

	// Delete the Deployment
	err = clientset.AppsV1().Deployments("attestation-system").Delete(context.TODO(), deploymentName, metav1.DeleteOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to delete Agent deployment: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return fmt.Errorf("Failed to delete Agent deplooyment: %v", err)
	}
	fmt.Printf(yellow.Sprintf("[%s] Agent Deployment '%s' successfully deleted\n", time.Now().Format("02-01-2006 15:04:05"), deploymentName))
	return nil
}

// Check if Node being considered is Control Plane
func nodeIsControlPlane(node *corev1.Node) bool {
	_, exists := node.Labels["node-role.kubernetes.io/control-plane"]
	return exists
}

func workerRemoval(removedWorkerName string) error {
	registrarWorkerDeletionURL := fmt.Sprintf("http://%s:%s/worker/deleteByName?name=%s", registrarHOST, registrarPORT, removedWorkerName)

	// Create a new HTTP request
	req, err := http.NewRequest(http.MethodDelete, registrarWorkerDeletionURL, nil)
	if err != nil {
		return fmt.Errorf("Error creating Worker Node removal request: %v", err)

	}
	// Send the request using the default HTTP client
	client := &http.Client{}
	resp, err := client.Do(req)
	if err != nil {
		return fmt.Errorf("Error sending Worker Node removal request: %v", err)

	}
	defer func(Body io.ReadCloser) {
		err := Body.Close()
		if err != nil {
			return
		}
	}(resp.Body)

	// Check the response status
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Failed to remove Worker Node from Registrar: received status code %d", resp.StatusCode)
	}

	fmt.Printf(yellow.Sprintf("[%s] Worker Node: '%s' removed from Registrar with success\n", time.Now().Format("02-01-2006 15:04:05"), removedWorkerName))
	return nil
}

func waitForAgent(retryInterval, timeout time.Duration, agentHOST, agentPORT string) error {
	address := fmt.Sprintf("%s:%s", agentHOST, agentPORT)
	start := time.Now()

	for {
		// Try to establish a TCP connection to the host
		conn, err := net.DialTimeout("tcp", address, retryInterval)
		if err == nil {
			// If the connection is successful, close it and return
			err := conn.Close()
			if err != nil {
				return err
			}
			return nil
		}

		// Check if the timeout has been exceeded
		if time.Since(start) > timeout {
			return fmt.Errorf("timeout: Agent is not reachable after %v", timeout)
		}

		// Wait for the retry interval before trying again
		time.Sleep(retryInterval)
	}
}

// workerRegistration registers the worker node by calling the identification API
func workerRegistration(newWorker *corev1.Node, agentHOST, agentPORT string) bool {
	agentIdentifyURL := fmt.Sprintf("http://%s:%s/agent/worker/registration/identify", agentHOST, agentPORT)
	agentChallengeNodeURL := fmt.Sprintf("http://%s:%s/agent/worker/registration/challenge", agentHOST, agentPORT)
	agentAcknowledgeURL := fmt.Sprintf("http://%s:%s/agent/worker/registration/acknowledge", agentHOST, agentPORT)
	registrarWorkerCreationURL := fmt.Sprintf("http://%s:%s/worker/create", registrarHOST, registrarPORT)

	err := waitForAgent(5*time.Second, 1*time.Minute, agentHOST, agentPORT)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while contacting Agent: %v\n", time.Now().Format("02-01-2006 15:04:05"), err.Error()))
		return false
	}

	// Call Agent to identify worker data
	workerData, err := getWorkerRegistrationData(agentIdentifyURL)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to start Worker registration: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// TEST: this allows the agent in 'simulator' mode to be compliant with the framework
	if workerData.EKCert != "EK Certificate not provided" {
		EKCertCheckRequest := model.VerifyTPMEKCertificateRequest{
			EndorsementKey: workerData.EK,
			EKCertificate:  workerData.EKCert,
		}
		err = registrar.VerifyEKCertificate(EKCertCheckRequest)
		if err != nil {
			fmt.Printf(red.Sprintf("[%s] Failed to verify EK Certificate: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
			return false
		}
	}

	// Decode EK and AIK
	EK, err := cryptoUtils.DecodePublicKeyFromPEM(workerData.EK)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to parse EK from PEM: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	AIKPublicKey, err := tpm_attestation.ValidateAIKPublicData(workerData.AIKNameData, workerData.AIKPublicArea)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to validate received Worker AIK: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// Generate ephemeral key
	ephemeralKey, err := cryptoUtils.GenerateEphemeralKey(ephemeralKeySize)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to generate challenge ephemeral key: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// Some TPMs cannot process secrets > 32 bytes, so first 8 bytes of the ephemeral key are used as nonce of quote computation
	quoteNonce := hex.EncodeToString(ephemeralKey[:8])

	encodedCredentialBlob, encodedEncryptedSecret, err := tpm_attestation.GenerateCredentialActivation(workerData.AIKNameData, EK, ephemeralKey)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to generate AIK credential activation challenge: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// Prepare challenge payload for sending
	workerChallenge := model.WorkerChallenge{
		AIKCredential:      encodedCredentialBlob,
		AIKEncryptedSecret: encodedEncryptedSecret,
	}

	// Send challenge request to the agent
	challengeResponse, err := sendChallengeRequest(agentChallengeNodeURL, workerChallenge)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to send challenge request: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	decodedHMAC, err := base64.StdEncoding.DecodeString(challengeResponse.HMAC)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to decode HMAC: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	// Verify the HMAC response from the agent
	if err := cryptoUtils.VerifyHMAC([]byte(workerData.UUID), ephemeralKey, decodedHMAC); err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to verify HMAC: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	bootAggregate, hashAlg, err := validateWorkerQuote(challengeResponse.WorkerBootQuote, quoteNonce, AIKPublicKey)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to validate Worker Quote: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	workerWhitelistCheckRequest := model.WorkerWhitelistCheckRequest{
		OsName:        newWorker.Status.NodeInfo.OSImage,
		BootAggregate: bootAggregate,
		HashAlg:       hashAlg,
	}

	err = verifyBootAggregate(workerWhitelistCheckRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Worker Boot validation failed: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	AIKPublicKeyPEM := cryptoUtils.EncodePublicKeyToPEM(AIKPublicKey)
	if AIKPublicKeyPEM == "" {
		fmt.Printf(red.Sprintf("[%s] Failed to parse AIK Public Key to PEM format\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	workerNode := model.WorkerNode{
		WorkerId: workerData.UUID,
		Name:     newWorker.GetName(),
		AIK:      AIKPublicKeyPEM,
	}

	// Create a new worker
	createWorkerResponse, err := createWorker(registrarWorkerCreationURL, &workerNode)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to create Worker Node: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
	}

	registrationAcknowledge := model.RegistrationAcknowledge{
		Message: createWorkerResponse.Message,
		Status:  createWorkerResponse.Status,
	}

	if createWorkerResponse.Status != "success" {
		registrationAcknowledge.VerifierPublicKey = ""
	} else {
		registrationAcknowledge.VerifierPublicKey = verifierPublicKey
	}

	err = workerRegistrationAcknowledge(agentAcknowledgeURL, registrationAcknowledge)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to acknowledge Worker Node about registration result: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	fmt.Printf(green.Sprintf("[%s] Successfully registered Worker Node '%s': %s\n", time.Now().Format("02-01-2006 15:04:05"), newWorker.GetName(), createWorkerResponse.WorkerId))
	return true
}

func validateWorkerQuote(quoteJSON, nonce string, AIK *rsa.PublicKey) (string, string, error) {
	// decode nonce from hex
	nonceBytes, err := hex.DecodeString(nonce)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode nonce: %v", err)
	}

	// Parse inputQuote JSON
	var workerQuote *model.InputQuote
	err = json.Unmarshal([]byte(quoteJSON), &workerQuote)
	if err != nil {
		return "", "", fmt.Errorf("failed to unmarshal worker quote: %v", err)
	}

	bootAggregate, hashAlg, err := tpm_attestation.ValidateWorkerQuote(workerQuote, nonceBytes, AIK)
	if err != nil {
		return "", "", fmt.Errorf("failed to validate worker quote: %v", err)
	}

	return bootAggregate, hashAlg, nil
}

func verifyBootAggregate(checkRequest model.WorkerWhitelistCheckRequest) error {
	whitelistProviderWorkerValidateURL := fmt.Sprintf("http://%s:%s/whitelist/worker/os/check", whitelistHOST, whitelistPORT)

	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(checkRequest)
	if err != nil {
		return fmt.Errorf("failed to marshal Whitelist check request: %v", err)
	}

	// Make the POST request to the agent
	resp, err := http.Post(whitelistProviderWorkerValidateURL, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send Whitelist check request: %v", err)
	}

	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Whitelist Provider failed to process check request: %s (status: %d)", string(body), resp.StatusCode)
	}
	return nil
}

// Helper function to call the agent identification API
func getWorkerRegistrationData(url string) (*model.WorkerResponse, error) {
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("failed to call agent identification API: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status is OK (200)
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Agent failed to process identification request: %s (status: %d)", string(body), resp.StatusCode)
	}

	var workerResponse model.WorkerResponse
	if err := json.Unmarshal(body, &workerResponse); err != nil {
		return nil, fmt.Errorf("failed to decode response: received %s: %v", string(body), err)
	}
	return &workerResponse, nil
}

// Helper function to call the agent identification API
func workerRegistrationAcknowledge(url string, acknowledge model.RegistrationAcknowledge) error {
	// Marshal the attestation request to JSON
	jsonPayload, err := json.Marshal(acknowledge)
	if err != nil {
		return fmt.Errorf("failed to marshal Registration cknowledge request: %v", err)
	}

	// Make the POST request to the agent
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonPayload))
	if err != nil {
		return fmt.Errorf("failed to send Registration acknowledge request: %v", err)
	}

	defer resp.Body.Close()

	// Read response body
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("failed to read response body: %v", err)
	}

	// Check if the status is OK (200) or created (201)
	if resp.StatusCode != http.StatusCreated && resp.StatusCode != http.StatusOK {
		return fmt.Errorf("Agent failed to acknowledge registration: %s (status: %d)", string(body), resp.StatusCode)
	}
	return nil
}

// Helper function to send the challenge request to the agent
func sendChallengeRequest(url string, challenge model.WorkerChallenge) (*model.WorkerChallengeResponse, error) {
	// Marshal the challenge struct into JSON
	jsonData, err := json.Marshal(challenge)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal challenge payload: %v", err)
	}

	// Send HTTP POST request
	resp, err := http.Post(url, "application/json", bytes.NewBuffer(jsonData))
	if err != nil {
		return nil, fmt.Errorf("failed to send challenge request: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		bodyBytes, _ := io.ReadAll(resp.Body) // Read the body
		return nil, fmt.Errorf("unexpected response status: %s, response body: %s", resp.Status, string(bodyBytes))
	}

	// Decode the response JSON into the WorkerChallengeResponse struct
	var challengeResponse model.WorkerChallengeResponse
	if err := json.NewDecoder(resp.Body).Decode(&challengeResponse); err != nil {
		return nil, fmt.Errorf("failed to decode challenge response: %v", err)
	}

	return &challengeResponse, nil
}

func createAgentCRDInstance(nodeName string) bool {
	// Get the list of pods running on the specified node and attestation namespace
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error getting pods on Node '%s': %v\n", time.Now().Format("02-01-2006 15:04:05"), nodeName, err))
		return false
	}

	// Prepare podStatus array for the Agent CRD spec
	var podStatus []map[string]interface{}
	for _, pod := range pods.Items {

		// do not add pods that are not deployed within a namespace enabled for attestation
		if !isNamespaceEnabledForAttestation(pod.GetNamespace()) {
			continue
		}

		podName := pod.Name
		tenantID := pod.Annotations["tenantID"]

		// Skip pods with name prefixed with "agent-"
		if strings.HasPrefix(podName, "agent-") {
			continue
		}

		// Add each pod status to the array
		podStatus = append(podStatus, map[string]interface{}{
			"podName":   podName,
			"tenantID":  tenantID,
			"status":    "TRUSTED",
			"reason":    "Agent just created",
			"lastCheck": time.Now().Format(time.RFC3339),
		})
	}

	// Construct the Agent CRD instance
	agent := &unstructured.Unstructured{
		Object: map[string]interface{}{
			"apiVersion": "example.com/v1",
			"kind":       "Agent",
			"metadata": map[string]interface{}{
				"name":      fmt.Sprintf("agent-%s", nodeName),
				"namespace": "attestation-system",
			},
			"spec": map[string]interface{}{
				"agentName":  fmt.Sprintf("agent-%s", nodeName),
				"nodeStatus": "TRUSTED",
				"podStatus":  podStatus,
				"lastUpdate": time.Now().Format(time.RFC3339),
			},
		},
	}

	// Define the resource to create
	gvr := schema.GroupVersionResource{
		Group:    "example.com", // Group name defined in your CRD
		Version:  "v1",
		Resource: "agents",
	}

	// Create the Agent CRD instance in the kube-system namespace
	_, err = dynamicClient.Resource(gvr).Namespace("attestation-system").Create(context.TODO(), agent, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf(yellow.Sprintf("[%s] Error creating Agent CRD instance: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return false
	}

	fmt.Printf(green.Sprintf("[%s] Agent CRD instance created for Node '%s'\n", time.Now().Format("02-01-2006 15:04:05"), nodeName))
	return true
}

func deployAgentCRD() {
	// Define the CustomResourceDefinition
	crd := &apiextensionsv1.CustomResourceDefinition{
		ObjectMeta: metav1.ObjectMeta{
			Name: "agents.example.com",
		},
		Spec: apiextensionsv1.CustomResourceDefinitionSpec{
			Group: "example.com",
			Names: apiextensionsv1.CustomResourceDefinitionNames{
				Kind:     "Agent",
				ListKind: "AgentList",
				Plural:   "agents",
				Singular: "agent",
			},
			Scope: apiextensionsv1.NamespaceScoped,
			Versions: []apiextensionsv1.CustomResourceDefinitionVersion{
				{
					Name:    "v1",
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
														"tenantID": {
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
	agentCRD, err := apiExtensionsClient.ApiextensionsV1().CustomResourceDefinitions().Create(context.TODO(), crd, metav1.CreateOptions{})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error creating Agent CRD: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return
	}

	fmt.Printf(green.Sprintf("[%s] CRD '%s' created successfully\n", time.Now().Format("02-01-2006 15:04:05"), agentCRD.Name))
}

func deleteAgentCRDInstance(nodeName string) error {
	// Construct the name of the Agent CRD based on the node name
	agentCRDName := fmt.Sprintf("agent-%s", nodeName)

	// Define the GroupVersionResource for the Agent CRD
	gvr := schema.GroupVersionResource{
		Group:    "example.com", // Group name defined in your CRD
		Version:  "v1",
		Resource: "agents", // Plural form of the CRD resource name
	}

	// Delete the Agent CRD instance in the "kube-system" namespace
	err := dynamicClient.Resource(gvr).Namespace("attestation-system").Delete(context.TODO(), agentCRDName, metav1.DeleteOptions{})
	if err != nil {
		return fmt.Errorf("Error deleting Agent CRD instance: %v\n", err)

	}
	fmt.Printf(yellow.Sprintf("[%s] Agent CRD instance deleted: %s\n", time.Now().Format("02-01-2006 15:04:05"), agentCRDName))
	return nil
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}

// Main function
func main() {
	initializeColors()
	loadEnvironmentVariables()
	configureKubernetesClient()

	deployAgentCRD()

	stopCh := setupSignalHandler()

	watchNodes(stopCh)
}
