package verifier

import (
	"context"
	"crypto"
	"encoding/json"
	"fmt"
	"github.com/franc-zar/go-ima/pkg"
	"github.com/golang-jwt/jwt/v5"
	pb "github.com/google/go-tpm-tools/proto/tpm"
	"github.com/torsec/k8s-pod-attestation/pkg/agent"
	"github.com/torsec/k8s-pod-attestation/pkg/cluster_interaction"
	cryptoUtils "github.com/torsec/k8s-pod-attestation/pkg/crypto"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"github.com/torsec/k8s-pod-attestation/pkg/registrar"
	"github.com/torsec/k8s-pod-attestation/pkg/tpm_attestation"
	"github.com/torsec/k8s-pod-attestation/pkg/whitelist"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/tools/cache"
	"os"
	"os/signal"
	"syscall"
	"time"
)

const AttestationNonceSize = 16
const eatNonceSize = 8
const attestationResultIssuer = "RA-Engine"

const DefaultHashAlgo = crypto.SHA256

type Verifier struct {
	clusterInteractor cluster_interaction.ClusterInteraction
	informerFactory   dynamicinformer.DynamicSharedInformerFactory
	agentClient       agent.Client
	registrarClient   *registrar.Client
	whitelistClient   *whitelist.Client
	attestationSecret []byte
	privateKey        crypto.PrivateKey
	validator         *ima.Validator
	podsIntegrity     map[string]*ima.Integrity
}

func (v *Verifier) Init(defaultResync int, attestationSecret []byte, privateKey crypto.PrivateKey, registrarClient *registrar.Client, whitelistClient *whitelist.Client) {
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
	v.podsIntegrity = make(map[string]*ima.Integrity)
}

func (v *Verifier) createAgentAttestationRequest(attestationRequest *cluster_interaction.AttestationRequest) (*model.AttestationRequest, error) {
	_, err := attestationRequest.ValidateHMAC(v.attestationSecret)
	if err != nil {
		return nil, fmt.Errorf("invalid Attestation Request CRD: %s", err)
	}

	nonce, err := cryptoUtils.GetNonce(AttestationNonceSize)
	if err != nil {
		return nil, fmt.Errorf("failed to generate nonce for Attestation Request")
	}

	mlOffset := int64(0)
	integrity, exists := v.podsIntegrity[attestationRequest.Spec.PodUid]
	if exists {
		mlOffset = integrity.Offset()
	}

	agentAttestationRequest := &model.AttestationRequest{
		Nonce:  nonce,
		Offset: mlOffset,
	}

	err = agentAttestationRequest.Sign(v.privateKey, DefaultHashAlgo)
	if err != nil {
		return nil, fmt.Errorf("error while signing Attestation Request")
	}

	return agentAttestationRequest, nil
}

func (v *Verifier) validatePodQuote(workerName string, podQuote *pb.Quote, nonce []byte) error {
	err := tpm_attestation.ValidateQuoteStructure(podQuote, nonce)
	if err != nil {
		return fmt.Errorf("failed to validate Quote Structure: %s", err)
	}

	quoteSignature, hashAlgo, err := tpm_attestation.GetQuoteSignature(podQuote)
	if err != nil {
		return fmt.Errorf("failed to get quote signature: %v", err)
	}

	quoteSignatureValidationRequest := &model.VerifySignatureRequest{
		Name:    workerName,
		Message: podQuote.Quote,
		Signature: &model.Signature{
			RawSignature: quoteSignature,
			HashAlg:      hashAlgo,
		},
	}

	quoteSignatureValidationResponse, err := v.registrarClient.VerifyWorkerSignature(quoteSignatureValidationRequest)
	if err != nil {
		return fmt.Errorf("failed to validate quote signature: %v", err)
	}

	if quoteSignatureValidationResponse.Status != model.Success {
		return fmt.Errorf("invalid quote signature: %v", quoteSignatureValidationResponse.Message)
	}

	return nil
}

func (v *Verifier) podAttestation(attestationRequest *cluster_interaction.AttestationRequest) (*model.AttestationResult, error) {
	agentPort, err := v.clusterInteractor.GetAgentPort(attestationRequest.Spec.AgentName)
	if err != nil {
		return nil, fmt.Errorf("error while sending Attestation Request to Agent: service port not found")
	}

	v.agentClient.Init(attestationRequest.Spec.AgentIP, agentPort, nil)

	agentAttestationRequest, err := v.createAgentAttestationRequest(attestationRequest)
	if err != nil {
		return nil, fmt.Errorf("error while creating Agent Attestation Request: %v", err)
	}

	attestationResponse, err := v.agentClient.PodAttestation(agentAttestationRequest)
	if err != nil {
		return nil, fmt.Errorf("error while sending Attestation Request to Agent: %v", err)
	}

	if attestationResponse.Status != model.Success {
		return nil, fmt.Errorf("invalid attestation response: %v", attestationResponse.Message)
	}

	// Serialize Evidence struct to JSON
	workerName, err := extractNodeName(attestationRequest.Spec.AgentName)
	if err != nil {
		return nil, fmt.Errorf("error while verifying Attestation Evidence: invalid Worker name")
	}

	evidence, err := model.EvidenceFromJSON(attestationResponse.Evidence)
	if err != nil {
		return nil, fmt.Errorf("error while verifying Attestation Evidence: %v", err)
	}

	quoteRaw, err := evidence.GetClaim(model.IMAPcrQuoteClaimKey)
	if err != nil {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.NodeResult{
				Name:   workerName,
				Result: model.UntrustedNodeStatus,
				Reason: "failed to get quote claim",
			},
		}, fmt.Errorf("failed to get quote claim: %v", err)
	}

	// Parse inputQuote JSON
	var quote *pb.Quote
	err = json.Unmarshal(quoteRaw, &quote)
	if err != nil {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.NodeResult{
				Name:   workerName,
				Result: model.UntrustedNodeStatus,
				Reason: "failed to process evidence Quote",
			},
		}, fmt.Errorf("failed to process evidence quote")
	}

	err = v.validatePodQuote(workerName, quote, agentAttestationRequest.Nonce)
	if err != nil {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.NodeResult{
				Name:   workerName,
				Result: model.UntrustedNodeStatus,
				Reason: fmt.Sprintf("Error while validating Worker Quote: %v", err),
			},
		}, fmt.Errorf("error while validating Worker Quote: %v", err)
	}

	imaMlRaw, err := evidence.GetClaim(model.IMAMeasurementLogClaimKey)
	if err != nil {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.NodeResult{
				Name:   workerName,
				Result: model.UntrustedNodeStatus,
				Reason: "failed to get measurement list claim",
			},
		}, fmt.Errorf("failed to get measurement list claim: %v", err)
	}

	imaMl := ima.NewMeasurementListFromRaw(imaMlRaw, 0)
	cgPathTarget, err := ima.NewCGPathTarget([]byte(attestationRequest.Spec.PodUid), ima.Containerd)
	if err != nil {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.NodeResult{
				Name:   workerName,
				Result: model.UntrustedNodeStatus,
				Reason: "Invalid container runtime attestation requested",
			},
		}, fmt.Errorf("invalid container runtime attestation requested")
	}

	expected := quote.GetPcrs().GetPcrs()[attestationResponse.ImaPcr]

	integrity, exists := v.podsIntegrity[attestationRequest.Spec.PodUid]
	if !exists {
		integrity, err = ima.NewIntegrity(
			attestationResponse.ImaPcr,
			attestationResponse.TemplateHashAlgo,
			attestationResponse.FileHashAlgo,
			nil,
			0,
		)
		if err != nil {
			return nil, fmt.Errorf("failed to create integrity tracker for attested pod")
		}
	}

	validator := ima.NewCgPathValidator(imaMl, integrity, cgPathTarget)
	err = validator.MeasurementListAttestation(expected)
	if err != nil {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.NodeResult{
				Name:   workerName,
				Result: model.UntrustedNodeStatus,
				Reason: fmt.Sprintf("Failed to validate IMA Measurement list: %s", err),
			},
		}, fmt.Errorf("failed to validate IMA Measurement list: %v", err)
	}

	podImageName, podImageDigest, err := v.clusterInteractor.GetPodImageDataByUid(attestationRequest.Spec.PodUid)
	if err != nil {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.PodResult{
				Name:     attestationRequest.Spec.PodName,
				TenantId: attestationRequest.Spec.TenantId,
				Result:   model.UntrustedPodStatus,
				Reason:   "Failed to get image name and digest of attested Pod",
			},
		}, fmt.Errorf("failed to get image name of attested Pod: %v", err)
	}

	podCheckRequest := &model.PodWhitelistCheckRequest{
		ImageName:   podImageName,
		ImageDigest: podImageDigest,
		Files:       cgPathTarget.GetMatches().Measurements[ima.Pod],
		HashAlg:     integrity.FileHashAlgo,
	}

	containerRuntimeCheckRequest := &model.ContainerRuntimeCheckRequest{
		Name:         ima.Containerd,
		Dependencies: cgPathTarget.GetMatches().Measurements[ima.ContainerRuntime],
		HashAlg:      integrity.FileHashAlgo,
	}

	containerRuntimeValidationResponse, err := v.whitelistClient.CheckContainerRuntimeWhitelist(containerRuntimeCheckRequest)
	if err != nil {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.NodeResult{
				Name:   workerName,
				Result: model.UntrustedNodeStatus,
				Reason: "Failed to verify integrity of Container Runtime",
			},
		}, fmt.Errorf("failed to verify integrity of Container Runtime: %v", err)
	}

	if containerRuntimeValidationResponse.Status != model.Success {
		logger.Warning("Container Runtime dependencies on Worker node '%s'; %s", workerName, containerRuntimeValidationResponse.ErroredEntries.ToString())
	} else {
		attestedContainerRuntimeDependencies, err := json.Marshal(cgPathTarget.GetMatches().Measurements[ima.ContainerRuntime])
		if err != nil {
			logger.Error("Failed to marshal ima container runtime dependencies as json")
		}
		logger.Success("Container Runtime attestation of Worker node '%s' completed with success; Successfully attested dependencies: %s", workerName, attestedContainerRuntimeDependencies)
	}

	podValidationResponse, err := v.whitelistClient.CheckPodWhitelist(podCheckRequest)
	if err != nil {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.PodResult{
				Name:     attestationRequest.Spec.PodName,
				TenantId: attestationRequest.Spec.TenantId,
				Result:   model.UntrustedPodStatus,
				Reason:   "Failed to verify integrity of files executed by attested Pod",
			},
		}, fmt.Errorf("failed to verify integrity of files executed by Pod: %v", err)
	}

	if podValidationResponse.Status != model.Success {
		logger.Warning("Pod '%s' executed over Worker node '%s' dependencies; %s;", attestationRequest.Spec.PodName, workerName, podValidationResponse.ErroredEntries.ToString())
	} else {
		attestedPodDependencies, err := json.Marshal(cgPathTarget.GetMatches().Measurements[ima.Pod])
		if err != nil {
			logger.Error("Failed to marshal ima pod entries as json")
		}
		logger.Success("Attestation of Pod '%s' executed over Worker node '%s' completed with success; Successfully attested dependencies: %s", attestationRequest.Spec.PodName, workerName, attestedPodDependencies)
	}

	trustedContainerRuntimeDependencies := filterTrustedDependencies(cgPathTarget.GetMatches().Measurements[ima.ContainerRuntime], &containerRuntimeValidationResponse.ErroredEntries)
	trustedPodDependencies := filterTrustedDependencies(cgPathTarget.GetMatches().Measurements[ima.Pod], &podValidationResponse.ErroredEntries)

	attestationResultJWT, isContainerRuntimeTrusted, isPodTrusted, err := v.createAttestationResult(
		attestationRequest.Spec.PodUid,
		trustedContainerRuntimeDependencies,
		trustedPodDependencies,
		&containerRuntimeValidationResponse.ErroredEntries,
		&podValidationResponse.ErroredEntries)
	if err != nil {
		logger.Error("Failed to create attestation result: %s", err)
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.PodResult{
				Name:     attestationRequest.Spec.PodName,
				TenantId: attestationRequest.Spec.TenantId,
				Result:   model.UntrustedPodStatus,
				Reason:   "Failed to create attestation result",
			},
		}, fmt.Errorf("failed to create attestation result: %v", err)
	}

	// TODO: send to RabbitMQ topic
	logger.Info("Attestation result: %s", attestationResultJWT)

	if !isContainerRuntimeTrusted {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.NodeResult{
				Name:   workerName,
				Result: model.UntrustedNodeStatus,
				Reason: "Untrusted Container Runtime",
			},
		}, fmt.Errorf("untrusted container runtime")
	}

	if !isPodTrusted {
		return &model.AttestationResult{
			Agent: attestationRequest.Spec.AgentName,
			Result: model.PodResult{
				Name:     attestationRequest.Spec.PodName,
				TenantId: attestationRequest.Spec.TenantId,
				Result:   model.UntrustedPodStatus,
				Reason:   "Untrusted Pod dependencies",
			},
		}, fmt.Errorf("untrusted pod")
	}

	v.podsIntegrity[attestationRequest.Spec.PodUid] = integrity

	return &model.AttestationResult{
		Agent: attestationRequest.Spec.AgentName,
		Result: model.PodResult{
			Name:     attestationRequest.Spec.PodName,
			TenantId: attestationRequest.Spec.TenantId,
			Result:   model.TrustedPodStatus,
			Reason:   "All Pod dependencies are trusted",
		},
	}, nil
}

func filterTrustedDependencies(attestedEntries []ima.Measurement, erroredEntries *model.ErroredEntries) []model.IndividualResult {
	var trustedEntries []model.IndividualResult
	for _, entry := range attestedEntries {
		isTrusted := true
		for _, erroredEntry := range erroredEntries.Absent {
			if entry.FilePath == erroredEntry.Id {
				isTrusted = false
				break
			}
		}
		if isTrusted {
			newResult := model.IndividualResult{
				Id:     entry.FilePath,
				Result: model.IrSuccess,
			}
			trustedEntries = append(trustedEntries, newResult)
		}
	}
	return trustedEntries
}

func (v *Verifier) createAttestationResult(podUid string, trustedContainerRuntimeEntries []model.IndividualResult, trustedPodEntries []model.IndividualResult, containerRuntimeErroredEntries *model.ErroredEntries, podErroredEntries *model.ErroredEntries) (string, bool, bool, error) {
	isTrusted := map[ima.MeasurementType]bool{ima.ContainerRuntime: false, ima.Pod: false}

	eatNonce, err := cryptoUtils.GetNonce(eatNonceSize)
	if err != nil {
		logger.Error("Failed to generate eat nonce")
		return "", false, false, fmt.Errorf("failed to generate eat nonce")
	}
	var measres []model.IndividualResult

	measres = append(measres, trustedContainerRuntimeEntries...)

	for _, erroredEntry := range containerRuntimeErroredEntries.Absent {
		newResult := model.IndividualResult{
			Id:     erroredEntry.Id,
			Result: model.IrAbsent,
		}
		measres = append(measres, newResult)
	}

	for _, erroredEntry := range containerRuntimeErroredEntries.NotRun {
		newResult := model.IndividualResult{
			Id:     erroredEntry.Id,
			Result: model.IrNotRun,
		}
		measres = append(measres, newResult)
	}

	for _, erroredEntry := range containerRuntimeErroredEntries.Mismatching {
		newResult := model.IndividualResult{
			Id:     erroredEntry.Id,
			Result: model.IrFail,
		}
		measres = append(measres, newResult)
	}

	measres = append(measres, trustedPodEntries...)

	for _, erroredEntry := range podErroredEntries.Absent {
		newResult := model.IndividualResult{
			Id:     erroredEntry.Id,
			Result: model.IrAbsent,
		}
		measres = append(measres, newResult)
	}

	for _, erroredEntry := range podErroredEntries.NotRun {
		newResult := model.IndividualResult{
			Id:     erroredEntry.Id,
			Result: model.IrNotRun,
		}
		measres = append(measres, newResult)
	}

	for _, erroredEntry := range podErroredEntries.Mismatching {
		newResult := model.IndividualResult{
			Id:     erroredEntry.Id,
			Result: model.IrFail,
		}
		measres = append(measres, newResult)
	}

	// create EAT and EAR
	eat := &model.EAT{
		Nonce:   eatNonce,
		Measres: measres,
	}

	var containerizationStatus model.StatusLabel
	switch {
	case len(containerRuntimeErroredEntries.Absent) > 0 || len(containerRuntimeErroredEntries.Mismatching) > 0:
		containerizationStatus = model.SlContraindicated
	case len(containerRuntimeErroredEntries.NotRun) > 0:
		containerizationStatus = model.SlWarning
		isTrusted[ima.ContainerRuntime] = true
	default:
		containerizationStatus = model.SlAffirming
		isTrusted[ima.ContainerRuntime] = true
	}

	var podStatus model.StatusLabel
	switch {
	case len(podErroredEntries.Absent) > 0 || len(podErroredEntries.Mismatching) > 0:
		podStatus = model.SlContraindicated
	case len(podErroredEntries.NotRun) > 0:
		podStatus = model.SlWarning
		isTrusted[ima.Pod] = true
	default:
		podStatus = model.SlAffirming
		isTrusted[ima.Pod] = true
	}

	submods := map[string]model.EARAppraisal{
		"system-boot": {
			Status: model.SlAffirming,
		},
		"containerization-dependencies": {
			Status: containerizationStatus,
		},
		fmt.Sprintf("pod-id:%s", podUid): {
			Status: podStatus,
		},
	}

	verifierId, err := os.Hostname()
	if err != nil {
		return "", false, false, fmt.Errorf("error getting verifier id: %v", err)

	}

	ear, err := model.NewEAR(eat, verifierId, submods)
	if err != nil {
		return "", false, false, fmt.Errorf("failed to create EAR: %v", err)
	}

	attestationResult, err := model.NewAttestationResult(model.CmwCollectionTypeAttestationResult)
	if err != nil {
		return "", false, false, fmt.Errorf("failed to create attestation result: %v", err)
	}

	earRaw, err := ear.ToJSON()
	if err != nil {
		return "", false, false, fmt.Errorf("failed to marshal EAR: %v", err)
	}

	result, err := model.NewCmwItem(model.EatJWTMediaType, earRaw, model.AttestationResultsIndicator)
	if err != nil {
		return "", false, false, fmt.Errorf("failed to create cmw item from EAR: %v", err)
	}

	err = attestationResult.AddCmwResult("ear", result)
	if err != nil {
		return "", false, false, err
	}

	attestationResultJWT, err := attestationResult.ToJWT(jwt.SigningMethodRS256, v.privateKey, attestationResultIssuer, 5)
	if err != nil {
		return "", false, false, fmt.Errorf("failed to create attestation result JWT: %v", err)
	}
	return attestationResultJWT, isTrusted[ima.ContainerRuntime], isTrusted[ima.Pod], nil
}

func extractNodeName(agentName string) (string, error) {
	prefix := "agent-"
	if len(agentName) > len(prefix) && agentName[:len(prefix)] == prefix {
		nodeName := agentName[len(prefix):]
		return nodeName, nil
	}
	return "", fmt.Errorf("invalid 'agentName' format: %s", agentName)
}

func (v *Verifier) addAttestationRequestHandling(obj interface{}) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		logger.Error("expected *unstructured.Unstructured but got %T", obj)
		return
	}

	var attestationRequest cluster_interaction.AttestationRequest
	err := attestationRequest.FromUnstructured(unstructuredObj)
	if err != nil {
		logger.Error("failed to parse attestation request: %v", err)
		return
	}

	attestationResult, failReason := v.podAttestation(&attestationRequest)

	_, err = v.clusterInteractor.DeleteAttestationRequest(attestationRequest.Name)
	if err != nil {
		logger.Error("failed to delete Attestation Request: %v", err)
		return
	}

	if attestationResult != nil {
		if failReason != nil {
			logger.Warning("Pod Attestation completed with negative outcome: %v; agent: '%s', target: '%s' name: '%s', result: '%s'", failReason, attestationResult.Agent, attestationResult.Result.GetKind(), attestationResult.Result.GetName(), attestationResult.Result.GetResult())
		} else {
			logger.Success("Pod Attestation completed with positive outcome; agent: '%s', target: '%s' name: '%s', result: '%s'", attestationResult.Agent, attestationResult.Result.GetKind(), attestationResult.Result.GetName(), attestationResult.Result.GetResult())
		}
		_, err = v.clusterInteractor.UpdateAgentCRDWithAttestationResult(attestationResult)
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
	unstructuredObj, ok := newObj.(*unstructured.Unstructured)
	if !ok {
		logger.Error("expected *unstructured.Unstructured but got %T", newObj)
		return
	}

	var attestationRequest cluster_interaction.AttestationRequest
	err := attestationRequest.FromUnstructured(unstructuredObj)
	if err != nil {
		logger.Error("failed to parse attestation request: %v", err)
		return
	}
	logger.Info("Attestation Request for pod: '%s' updated", attestationRequest.Spec.PodName)
}

func (v *Verifier) deleteAttestationRequestCRDHandling(obj interface{}) {
	unstructuredObj, ok := obj.(*unstructured.Unstructured)
	if !ok {
		logger.Error("expected *unstructured.Unstructured but got %T", obj)
		return
	}

	var attestationRequest cluster_interaction.AttestationRequest
	err := attestationRequest.FromUnstructured(unstructuredObj)
	if err != nil {
		logger.Error("failed to parse attestation request: %v", err)
		return
	}
	logger.Info("Attestation Request for pod: '%s' deleted", attestationRequest.Spec.PodName)
}

// WatchAttestationRequestCRDs starts watching for changes to the AttestationRequest CRD
// and processes added, modified, and deleted events.
func (v *Verifier) WatchAttestationRequestCRDs() {
	ctx := setupSignalHandler()
	// Get the informer for the AttestationRequest CRD
	attestationRequestInformer := v.informerFactory.ForResource(cluster_interaction.AttestationRequestGVR).Informer()

	// Add event handlers
	_, err := attestationRequestInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc:    v.addAttestationRequestHandling,
		UpdateFunc: v.updateAttestationRequestCRDHandling,
		DeleteFunc: v.deleteAttestationRequestCRDHandling,
	})
	if err != nil {
		logger.Fatal("failed to create Attestation Request CRD event handler: %v", err)
	}

	// Start the informer
	go attestationRequestInformer.Run(ctx.Done())

	// Wait for the informer to sync
	if !cache.WaitForCacheSync(ctx.Done(), attestationRequestInformer.HasSynced) {
		logger.Error("Timed out waiting for caches to sync")
		return
	}

	// Keep running until stopped
	<-ctx.Done()
	logger.Info("Stopping Verifier...")
}

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
