package verifier

import (
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/agent"
	"github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"github.com/torsec/k8s-pod-attestation/pkg/whitelist"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const attestationNoncesize = 16

type Verifier struct {
	clusterInteractor *cluster_interaction.ClusterInteraction
	informerFactory   dynamicinformer.DynamicSharedInformerFactory
	agentClient 	  *agent.Client
	registrarClient 	*registrar.Client
	whitelistClient *whitelist.Client
	attestationSecret []byte
	privateKey        *rsa.PrivateKey
}

func (v *Verifier) Init(attestationEnabledNamespaces []string, defaultResync int, attestationSecret []byte, privateKey *rsa.PrivateKey, registrarClient *registrar.Client, whitelistClient whitelist.Client) error {
	v.clusterInteractor.AttestationEnabledNamespaces = attestationEnabledNamespaces
	v.clusterInteractor.ConfigureKubernetesClient()
	v.informerFactory = dynamicinformer.NewFilteredDynamicSharedInformerFactory(v.clusterInteractor.DynamicClient, time.Minute*time.Duration(defaultResync), cluster_interaction.PodAttestationNamespace, nil)
	v.attestationSecret = attestationSecret
	v.privateKey = privateKey
	v.registrarClient = registrarClient
	v.whitelistClient = whitelistClient
}

func (v *Verifier) parseAttestationRequestFromCRD(spec map[string]interface{}) (*model.AttestationRequest, error) {
	podName, exists := spec["podName"].(string)
	if !exists {
		return nil, fmt.Errorf("missing 'podName' field in Attestation Request CRD")
	}

	podUid, exists := spec["podUid"].(string)
	if !exists {
		return nil, fmt.Errorf("missing 'podUid' field in Attestation Request CRD")
	}

	tenantId, exists := spec["tenantId"].(string)
	if !exists {
		return nil, fmt.Errorf("missing 'tenantId' field in Attestation Request CRD")
	}

	agentIP, exists := spec["agentIP"].(string)
	if !exists {
		return nil, fmt.Errorf("missing 'agentIP' field in Attestation Request CRD")
	}

	agentName, exists := spec["agentName"].(string)
	if !exists {
		return nil, fmt.Errorf("missing 'agentName' field in Attestation Request CRD")
	}

	hmac, exists := spec["hmac"].(string)
	if !exists {
		return nil, fmt.Errorf("missing 'hmac' field in Attestation Request CRD")
	}

	_, err := v.validateAttestationRequestCRD(hmac, podName, podUid, tenantId, agentName, agentIP)
	if err != nil {
		return nil, fmt.Errorf("invalid Attestation Request CRD: %s", err)
	}

	nonce, err := cryptoUtils.GenerateHexNonce(attestationNoncesize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce for Attestation Request")
	}

	attestationRequest := &model.AttestationRequest{
		Nonce:    nonce,
		PodName:  podName,
		PodUid:   podUid,
		TenantId: tenantId,
	}

	attestationRequestJSON, err := json.Marshal(attestationRequest)
	if err != nil {
		return nil, fmt.Errorf("error while serializing Attestation Request")
	}

	attestationRequestSignature, err := cryptoUtils.SignMessage(v.privateKey, attestationRequestJSON)
	if err != nil {
		return nil, fmt.Errorf("error while signing Attestation Request")
	}
	attestationRequest.Signature = attestationRequestSignature

	return attestationRequest, nil
}

func (v *Verifier) validateAttestationRequestCRD(hmac, podName, podUid, tenantId, agentName, agentIP string) (bool, error) {
	decodedHMAC, err := base64.StdEncoding.DecodeString(hmac)
	if err != nil {
		return false, fmt.Errorf("failed to decode HMAC: %v", err)
	}

	integrityMessage := fmt.Sprintf("%s::%s::%s::%s::%s", podName, podUid, tenantId, agentName, agentIP)
	err = cryptoUtils.VerifyHMAC([]byte(integrityMessage), v.attestationSecret, decodedHMAC)
	if err != nil {
		return false, fmt.Errorf("failed to validate Attestation request HMAC: %v", err)
	}
	return true, nil
}

func (v *Verifier) podAttestation(attestationRequestCRDSpec map[string]interface{}) (*model.AttestationResult, error) {
	attestationRequest, err := v.parseAttestationRequestFromCRD(attestationRequestCRDSpec)
	if err != nil {
		return nil, fmt.Errorf("failed to parse attestation request: %v", err)
	}

	agentIP, exists := attestationRequestCRDSpec["agentIP"].(string)
	if !exists {
		return nil, fmt.Errorf("missing 'agentIP' field in Attestation Request CRD")
	}

	agentName, exists := attestationRequestCRDSpec["agentName"].(string)
	if !exists {
		return nil, fmt.Errorf("missing 'agentName' field in Attestation Request CRD")
	}

	agentPort, err := v.clusterInteractor.GetAgentPort(agentName)
	if err != nil {
		return nil, fmt.Errorf("error while sending Attestation Request to Agent: service port not found")
	}

	v.agentClient.Init(agentIP, agentPort, nil)

	v.agentClient.WorkerRegistrationChallenge()


	attestationResponse, err := sendAttestationRequestToAgent(agentIP, agentPort, attestationRequest)
	if err != nil {
		return nil, fmt.Errorf("error while sending Attestation Request to Agent")
	}

	workerName, err := extractNodeName(agentName)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error while verifying Attestation Evidence: invalid Worker name\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Error while verifying Attestation Evidence: invalid Worker name")
	}

	evidenceDigest, err := computeEvidenceDigest(attestationResponse.Evidence)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error computing Evidence digest\n", time.Now().Format("02-01-2006 15:04:05")))
		return nil, fmt.Errorf("Error computing Evidence digest")
	}

	// process Evidence
	_, err = verifyWorkerSignature(workerName, evidenceDigest, attestationResponse.Signature)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Evidence Signature Verification failed: %s\n", time.Now().Format("02-01-2006 15:04:05"), err.Error()))
		return &AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     "UNTRUSTED",
			Reason:     "Evidence Signature verification failed",
		}, fmt.Errorf("Evidence Signature verification failed")
	}

	PCR10Digest, hashAlg, err := validateWorkerQuote(workerName, attestationResponse.Evidence.WorkerQuote, nonce)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to validate Worker Quote: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return &AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     "UNTRUSTED",
			Reason:     "Error while validating Worker Quote",
		}, fmt.Errorf("Error while validating Worker Quote")
	}

	IMAPodEntries, IMAContainerRuntimeEntries, err := IMAVerification(attestationResponse.Evidence.WorkerIMA, PCR10Digest, podUID)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to validate IMA measurement logger: %v\n", time.Now().Format("02-01-2006 15:04:05"), err))
		return &AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     "UNTRUSTED",
			Reason:     "Failed to validate IMA Measurement logger",
		}, fmt.Errorf("Failed to validate IMA Measurement logger")
	}

	podImageName, podImageDigest, err := getPodImageDataByUID(podUID)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to get image name and digest of Pod: %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), podName, err))
		return &AttestationResult{
			Agent:      agentName,
			Target:     podName,
			TargetType: "Pod",
			Result:     "UNTRUSTED",
			Reason:     "Failed to get image name and digest of attested Pod",
		}, fmt.Errorf("Failed to get image name of attested Pod")
	}

	podCheckRequest := PodWhitelistCheckRequest{
		PodImageName:   podImageName,
		PodImageDigest: podImageDigest,
		PodFiles:       IMAPodEntries,
		HashAlg:        hashAlg,
	}

	containerRuntimeCheckRequest := ContainerRuntimeCheckRequest{
		ContainerRuntimeName:         containerRuntimeName,
		ContainerRuntimeDependencies: IMAContainerRuntimeEntries,
		HashAlg:                      hashAlg,
	}

	err = verifyContainerRuntimeIntegrity(containerRuntimeCheckRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to verify integrity of Container Runtime: %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), containerRuntimeCheckRequest.ContainerRuntimeName, err))
		return &AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     "UNTRUSTED",
			Reason:     "Failed to verify integrity of Container Runtime",
		}, fmt.Errorf("Failed to verify integrity of Container Runtime")
	}

	err = verifyPodFilesIntegrity(podCheckRequest)
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Failed to verify integrity of files executed by Pod: %s: %v\n", time.Now().Format("02-01-2006 15:04:05"), podName, err))
		return &AttestationResult{
			Agent:      agentName,
			Target:     podName,
			TargetType: "Pod",
			Result:     "UNTRUSTED",
			Reason:     "Failed to verify integrity of files executed by attested Pod",
		}, fmt.Errorf("Failed to verify integrity of files executed by Pod")
	}

	fmt.Printf(green.Sprintf("[%s] Attestation of Pod: %s succeeded\n", time.Now().Format("02-01-2006 15:04:05"), podName))
	return &AttestationResult{
		Agent:      agentName,
		Target:     podName,
		TargetType: "Pod",
		Result:     "TRUSTED",
		Reason:     "Attestation ended with success",
	}, nil
}

func extractNodeName(agentName string) (string, error) {
	prefix := "agent-"
	if len(agentName) > len(prefix) && agentName[:len(prefix)] == prefix {
		nodeName := agentName[len(prefix):]
		return nodeName, nil
	}
	return "", fmt.Errorf("invalid 'agentName' format: %s", agentName)
}

func formatAttestationRequestCRD(obj interface{}) map[string]interface{} {
	agentCRD, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		logger.Error("failed to parse Agent CRD")
		return nil
	}

	spec, specExists := agentCRD["spec"].(map[string]interface{})
	if !specExists {
		logger.Error("Error: Missing 'spec' field in Agent CRD")
		return nil
	}
	return spec
}

func (v *Verifier) addAttestationRequestCRDHandling(obj interface{}) {
	attestationRequestCRD := formatAttestationRequestCRD(obj)
	if attestationRequest == nil {
		return
	}
	attestationResult, failReason := podAttestation(attestationRequestCRD)
	if attestationResult != nil {
		updateAgentCRDWithAttestationResult(attestationResult)
	} else if failReason != nil {
		deleteAttestationRequestCRDInstance(obj)
	}
}

func (v *Verifier) updateAttestationRequestCRDHandling(oldObj interface{}, newObj interface{}) {
	attestationRequest := formatAttestationRequestCRD(oldObj)
	if attestationRequest == nil {
		return
	}
	logger.Info("Attestation Request '%s' updated", attestationRequest["name"])
}

func (v *Verifier) deleteAttestationRequestCRDHandling(obj interface{}) {
	attestationRequest := formatAttestationRequestCRD(obj)
	if attestationRequest == nil {
		return
	}
	logger.Info("Attestation Request '%s' deleted", attestationRequest["name"])
}

// watchAttestationRequestCRDs starts watching for changes to the AttestationRequest CRD
// and processes added, modified, and deleted events.
func (v *Verifier) WatchAttestationRequestCRDs() {
	stopCh := setupSignalHandler()
	// Get the informer for the AttestationRequest CRD
	attestationRequestInformer := v.informerFactory.ForResource(cluster_interaction.AttestationRequestGVR).Informer()

	// Add event handlers
	_, err := attestationRequestInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    v.addAttestationRequestCRDHandling,
		UpdateFunc: v.updateAttestationRequestCRDHandling,
		DeleteFunc: v.deleteAttestationRequestCRDHandling,
	})
	if err != nil {
		logger.Fatal("failed to create Attestation Request CRD event handler: %v", err)
	}

	// Convert `chan os.Signal` to `<-chan struct{}`
	stopStructCh := make(chan struct{})
	go func() {
		<-stopCh // Wait for signal
		close(stopStructCh)
	}()

	// Start the informer
	go attestationRequestInformer.Run(stopStructCh)

	// Wait for the informer to sync
	if !cache.WaitForCacheSync(stopStructCh, attestationRequestInformer.HasSynced) {
		logger.Error("Timed out waiting for caches to sync"))
		return
	}

	// Keep running until stopped
	<-stopStructCh
	logger.Info("Stopping Attestation Request CRD watcher...")
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}
