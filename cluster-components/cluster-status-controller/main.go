package main

import (
	"context"
	"fmt"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/dynamic/dynamicinformer"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/tools/cache"
	"os"
	"time"
)

var (
	dynamicClient dynamic.Interface
	clientset     *kubernetes.Clientset
)

// loadEnvironmentVariables loads required environment variables and sets default values if necessary.
func loadEnvironmentVariables() {
}

// getEnv retrieves the value of an environment variable or returns a default value if not set.
func getEnv(key, defaultValue string) string {
	value := os.Getenv(key)
	if value == "" {
		return defaultValue
	}
	return value
}

func watchAgentCRDChanges(stopCh chan os.Signal) {
	// Define the GVR (GroupVersionResource) for the CRD you want to watch
	crdGVR := schema.GroupVersionResource{
		Group:    "example.com",
		Version:  "v1",
		Resource: "agents",
	}

	// Create a SharedInformerFactory
	informerFactory := dynamicinformer.NewFilteredDynamicSharedInformerFactory(dynamicClient, time.Minute*5, "attestation-system", nil)

	// Get the informer for the CRD
	agentInformer := informerFactory.ForResource(crdGVR).Informer()

	// Add event handlers
	agentInformer.AddEventHandler(cache.ResourceEventHandlerFuncs{
		AddFunc: func(obj interface{}) {
			fmt.Printf(green.Sprintf("[%s] Agent CRD Added:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(obj)))
		},
		UpdateFunc: func(oldObj, newObj interface{}) {
			fmt.Printf(blue.Sprintf("[%s] Agent CRD Modified:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(newObj)))
			checkAgentStatus(newObj)
		},
		DeleteFunc: func(obj interface{}) {
			fmt.Printf(yellow.Sprintf("[%s] Agent CRD Deleted:\n%s\n", time.Now().Format("02-01-2006 15:04:05"), formatAgentCRD(obj)))
		},
	})

	// Convert `chan os.Signal` to `<-chan struct{}`
	stopStructCh := make(chan struct{})
	go func() {
		<-stopCh // Wait for signal
		close(stopStructCh)
	}()

	// Start the informer
	go agentInformer.Run(stopStructCh)

	// Wait for the informer to sync
	if !cache.WaitForCacheSync(stopStructCh, agentInformer.HasSynced) {
		fmt.Println("Timed out waiting for caches to sync")
		return
	}

	// Keep running until stopped
	<-stopStructCh
	fmt.Println("Stopping application...")
}

func formatAgentCRD(obj interface{}) map[string]interface{} {
	agentCRD, err := runtime.DefaultUnstructuredConverter.ToUnstructured(obj)
	if err != nil {
		fmt.Println(red.Println("Error: Missing 'spec' field in Agent CRD"))
		return nil
	}

	spec, specExists := agentCRD["spec"].(map[string]interface{})
	if !specExists {
		fmt.Println(red.Println("Error: Missing 'spec' field in Agent CRD"))
		return nil
	}
	return spec
}

func deleteAllPodsFromNode(nodeName string) {
	// Get all pods on the specified node
	pods, err := clientset.CoreV1().Pods("").List(context.TODO(), metav1.ListOptions{
		FieldSelector: fmt.Sprintf("spec.nodeName=%s", nodeName),
	})
	if err != nil {
		fmt.Printf(red.Sprintf("[%s] Error listing pods on node %s: %v", time.Now().Format("02-01-2006 15:04:05"), nodeName, err))
		return
	}

	// Delete each pod on the node
	for _, pod := range pods.Items {
		err := clientset.CoreV1().Pods(pod.Namespace).Delete(context.TODO(), pod.Name, metav1.DeleteOptions{})
		if err != nil {
			fmt.Printf(red.Sprintf("[%s] Error deleting pod %s in namespace %s: %v", time.Now().Format("02-01-2006 15:04:05"), pod.Name, pod.Namespace, err))
			return
		}
		fmt.Printf(yellow.Sprintf("[%s] Deleted pod %s from untrusted node %s\n", time.Now().Format("02-01-2006 15:04:05"), pod.Name, nodeName))
	}

	fmt.Printf(yellow.Sprintf("[%s] Deleted all pods from untrusted node %s\n", time.Now().Format("02-01-2006 15:04:05"), nodeName))
}

func main() {
	initializeColors()
	configureKubernetesClient()

	stopCh := setupSignalHandler()

	watchAgentCRDChanges(stopCh)

	// Keep the application running until terminated
	fmt.Printf(green.Sprintf("Watching Agent CRD changes...\n\n"))
	<-stopCh
}
