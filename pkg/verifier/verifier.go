package verifier

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"github.com/torsec/k8s-pod-attestation/pkg/agent"
	"github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/ima"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"github.com/torsec/k8s-pod-attestation/pkg/tpm_attestation"
	"github.com/torsec/k8s-pod-attestation/pkg/whitelist"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const attestationNonceSize = 16

type Verifier struct {
	clusterInteractor cluster_interaction.ClusterInteraction
	informerFactory   dynamicinformer.DynamicSharedInformerFactory
	agentClient       agent.Client
	registrarClient   *registrar.Client
	whitelistClient   *whitelist.Client
	attestationSecret []byte
	privateKey        string
}

func (v *Verifier) Init(defaultResync int, attestationSecret []byte, privateKey string, registrarClient *registrar.Client, whitelistClient *whitelist.Client) {
	v.clusterInteractor.ConfigureKubernetesClient()
	err := v.clusterInteractor.DefineAttestationRequestCRD()
	if err != nil {
		logger.Error("Failed to initialize Verifier: %v", err)
	}
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

	nonce, err := cryptoUtils.GenerateHexNonce(attestationNonceSize)
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
	attestationRequest.Signature = base64.StdEncoding.EncodeToString(attestationRequestSignature)

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

func (v *Verifier) validatePodAttestationQuote(workerName string, podQuote *model.InputQuote, nonce string) (string, string, error) {
	nonceRaw, err := hex.DecodeString(nonce)
	if err != nil {
		return "", "", fmt.Errorf("failed to decode nonce from hex: %v", err)
	}
	quoteSignature, pcr10, hashAlgo, err := tpm_attestation.ValidatePodQuoteStructure(podQuote, nonceRaw)
	if err != nil {
		return "", "", fmt.Errorf("invalid pod quote structure: %v", err)
	}

	quoteSignatureValidationRequest := &model.VerifySignatureRequest{
		Name:      workerName,
		Message:   podQuote.Quote,
		Signature: quoteSignature,
	}

	quoteSignatureValidationResponse, err := v.registrarClient.VerifyWorkerSignature(quoteSignatureValidationRequest)
	if err != nil {
		return "", "", fmt.Errorf("failed to validate quote signature: %v", err)
	}

	if quoteSignatureValidationResponse.Status != model.Success {
		return "", "", fmt.Errorf("invalid quote signature")
	}
	return pcr10, hashAlgo, nil
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

	v.agentClient.Init(agentIP, int(agentPort), nil)

	attestationResponse, err := v.agentClient.PodAttestation(attestationRequest)
	if err != nil {
		return nil, fmt.Errorf("error while sending Attestation Request to Agent: %v", err)
	}

	if attestationResponse.Status != model.Success {
		return nil, fmt.Errorf("invalid attestation response: %v", attestationResponse.Message)
	}

	evidenceRaw, err := json.Marshal(attestationResponse.AttestationEvidence.Evidence)
	if err != nil {
		return nil, fmt.Errorf("failed to serialize Evidence: %v", err)
	}

	evidenceDigest, err := cryptoUtils.Hash(evidenceRaw)
	if err != nil {
		return nil, fmt.Errorf("error computing Attestation Evidence digest")
	}

	// Serialize Evidence struct to JSON
	workerName, err := extractNodeName(agentName)
	if err != nil {
		return nil, fmt.Errorf("error while verifying Attestation Evidence: invalid Worker name")
	}

	verifyWorkerSignatureRequest := &model.VerifySignatureRequest{
		Name:      workerName,
		Message:   base64.StdEncoding.EncodeToString(evidenceDigest),
		Signature: attestationResponse.AttestationEvidence.Signature,
	}

	// process Evidence
	workerSignatureVerificationResponse, err := v.registrarClient.VerifyWorkerSignature(verifyWorkerSignatureRequest)
	if err != nil {
		return &model.AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     cluster_interaction.UntrustedNodeStatus,
			Reason:     "Evidence signature verification failed",
		}, fmt.Errorf("evidence signature verification failed")
	}

	if workerSignatureVerificationResponse.Status != model.Success {
		return &model.AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     cluster_interaction.UntrustedNodeStatus,
			Reason:     "Invalid Evidence signature",
		}, fmt.Errorf("invalid evidence signature")
	}

	quoteJson, err := base64.StdEncoding.DecodeString(attestationResponse.AttestationEvidence.Evidence.Quote)
	if err != nil {
		return &model.AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     cluster_interaction.UntrustedNodeStatus,
			Reason:     "failed to decode Evidence Quote from base64",
		}, fmt.Errorf("failed to process evidence quote")
	}

	// Parse inputQuote JSON
	var inputQuote *model.InputQuote
	err = json.Unmarshal(quoteJson, &inputQuote)
	if err != nil {
		return &model.AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     cluster_interaction.UntrustedNodeStatus,
			Reason:     "failed to parse Evidence Quote",
		}, fmt.Errorf("failed to process evidence quote")
	}

	pcr10Content, pcrHashAlg, err := v.validatePodAttestationQuote(workerName, inputQuote, attestationRequest.Nonce)
	if err != nil {
		return &model.AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     cluster_interaction.UntrustedNodeStatus,
			Reason:     "Error while validating Worker Quote",
		}, fmt.Errorf("error while validating Worker Quote")
	}

	imaPodEntries, imaContainerRuntimeEntries, err := ima.MeasurementLogValidation(attestationResponse.AttestationEvidence.Evidence.MeasurementLog, pcr10Content, attestationRequest.PodUid)
	if err != nil {
		return &model.AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     cluster_interaction.UntrustedNodeStatus,
			Reason:     "Failed to validate IMA Measurement log",
		}, fmt.Errorf("failed to validate IMA Measurement log")
	}

	podImageName, podImageDigest, err := v.clusterInteractor.GetPodImageDataByUid(attestationRequest.PodUid)
	if err != nil {
		return &model.AttestationResult{
			Agent:      agentName,
			Target:     attestationRequest.PodName,
			TargetType: "Pod",
			Result:     cluster_interaction.UntrustedPodStatus,
			Reason:     "Failed to get image name and digest of attested Pod",
		}, fmt.Errorf("failed to get image name of attested Pod")
	}

	podCheckRequest := &model.PodWhitelistCheckRequest{
		PodImageName:   podImageName,
		PodImageDigest: podImageDigest,
		PodFiles:       imaPodEntries,
		HashAlg:        pcrHashAlg,
	}

	containerRuntimeCheckRequest := &model.ContainerRuntimeCheckRequest{
		ContainerRuntimeName:         ima.ContainerRuntimeName,
		ContainerRuntimeDependencies: imaContainerRuntimeEntries,
		HashAlg:                      pcrHashAlg,
	}

	logger.Info("pod entries: %s", imaPodEntries)
	logger.Info("container runtime entries: %s", imaContainerRuntimeEntries)

	containerRuntimeValidationResponse, err := v.whitelistClient.CheckContainerRuntimeWhitelist(containerRuntimeCheckRequest)
	if err != nil {
		return &model.AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     cluster_interaction.UntrustedNodeStatus,
			Reason:     "Failed to verify integrity of Container Runtime",
		}, fmt.Errorf("failed to verify integrity of Container Runtime")
	}

	if containerRuntimeValidationResponse.Status != model.Success {
		logger.Info("Untrusted Container Runtime on Worker node '%s'; Absent entries: %s; Not Run entries %s; Mismatching entries: %s;", workerName, containerRuntimeValidationResponse.ErroredEntries.AbsentWhitelistEntries, containerRuntimeValidationResponse.ErroredEntries.NotRunWhitelistEntries, containerRuntimeValidationResponse.ErroredEntries.MismatchingWhitelistEntries)
		return &model.AttestationResult{
			Agent:      agentName,
			Target:     workerName,
			TargetType: "Node",
			Result:     cluster_interaction.UntrustedNodeStatus,
			Reason:     fmt.Sprintf("Untrusted Container Runtime: %s", containerRuntimeValidationResponse.Message),
		}, fmt.Errorf("untrusted Container Runtime")
	}

	logger.Success("Container Runtime attestation of Worker node '%s' completed with success; Successfully attested dependencies: %s", workerName, imaContainerRuntimeEntries)

	podValidationResponse, err := v.whitelistClient.CheckPodWhitelist(podCheckRequest)
	if err != nil {
		return &model.AttestationResult{
			Agent:      agentName,
			Target:     attestationRequest.PodName,
			TargetType: "Pod",
			Result:     cluster_interaction.UntrustedPodStatus,
			Reason:     "Failed to verify integrity of files executed by attested Pod",
		}, fmt.Errorf("failed to verify integrity of files executed by Pod")
	}

	if podValidationResponse.Status != model.Success {
		logger.Info("Untrusted Pod '%s' executed over Worker node '%s'; Absent entries: %s; Not Run entries %s; Mismatching entries: %s;", attestationRequest.PodName, workerName, podValidationResponse.ErroredEntries.AbsentWhitelistEntries, podValidationResponse.ErroredEntries.NotRunWhitelistEntries, podValidationResponse.ErroredEntries.MismatchingWhitelistEntries)

		return &model.AttestationResult{
			Agent:      agentName,
			Target:     attestationRequest.PodName,
			TargetType: "Pod",
			Result:     cluster_interaction.UntrustedPodStatus,
			Reason:     fmt.Sprintf("Untrusted Pod: %s", podValidationResponse.Message),
		}, fmt.Errorf("untrusted Pod")
	}

	logger.Success("Attestation of Pod '%s' executed over Worker node '%s' completed with success; Successfully attested dependencies: %s", attestationRequest.PodName, workerName, imaPodEntries)

	return &model.AttestationResult{
		Agent:      agentName,
		Target:     attestationRequest.PodName,
		TargetType: "Pod",
		Result:     cluster_interaction.TrustedPodStatus,
		Reason:     "Pod Attestation ended with success",
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
	if attestationRequestCRD == nil {
		return
	}

	attestationResult, failReason := v.podAttestation(attestationRequestCRD)

	_, err := v.clusterInteractor.DeleteAttestationRequestCRDInstance(obj)
	if err != nil {
		logger.Error("failed to delete Attestation Request: %v", err)
	}

	if attestationResult != nil {
		if failReason != nil {
			logger.Warning("Pod Attestation completed with negative outcome: %v; agent: '%s', target: '%s' name: '%s', result: '%s'", failReason, attestationResult.Agent, attestationResult.TargetType, attestationResult.Target, attestationResult.Result)
		} else {
			logger.Success("Pod Attestation completed with positive outcome; agent: '%s', target: '%s' name: '%s', result: '%s'", attestationResult.Agent, attestationResult.TargetType, attestationResult.Target, attestationResult.Result)
		}
		_, err := v.clusterInteractor.UpdateAgentCRDWithAttestationResult(attestationResult)
		if err != nil {
			logger.Error("failed to update Agent CRD with Attestation Result: %v", err)
			return
		}
		return
	}

	if failReason != nil {
		logger.Error("failed to process Attestation Request: %v; Attestation not performed", failReason)
	}
}

func (v *Verifier) updateAttestationRequestCRDHandling(oldObj interface{}, newObj interface{}) {
	attestationRequest := formatAttestationRequestCRD(oldObj)
	if attestationRequest == nil {
		return
	}
	logger.Info("Attestation Request for pod: '%s' updated", attestationRequest["podName"])
}

func (v *Verifier) deleteAttestationRequestCRDHandling(obj interface{}) {
	attestationRequest := formatAttestationRequestCRD(obj)
	if attestationRequest == nil {
		return
	}
	logger.Info("Attestation Request for pod: '%s' deleted", attestationRequest["podName"])
}

// WatchAttestationRequestCRDs starts watching for changes to the AttestationRequest CRD
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
		logger.Error("Timed out waiting for caches to sync")
		return
	}

	// Keep running until stopped
	<-stopStructCh
	logger.Info("Stopping Verifier...")
}

// setupSignalHandler sets up a signal handler for graceful termination.
func setupSignalHandler() chan os.Signal {
	stopCh := make(chan os.Signal, 1)
	signal.Notify(stopCh, syscall.SIGINT, syscall.SIGTERM)
	return stopCh
}
