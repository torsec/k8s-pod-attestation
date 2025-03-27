package whitelist

import (
	"context"
	"crypto/x509"
	"errors"
	"github.com/gin-gonic/gin"
	"github.com/torsec/k8s-pod-attestation/pkg/logger"
	"github.com/torsec/k8s-pod-attestation/pkg/model"
	"go.mongodb.org/mongo-driver/bson"
	"go.mongodb.org/mongo-driver/mongo"
	"go.mongodb.org/mongo-driver/mongo/options"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

const (
	dbName                     = "whitelist"
	workerCollection           = "worker"
	podCollection              = "pod"
	containerRuntimeCollection = "container_runtime"
)

const (
	CheckWorkerWhitelistUrl      = "/whitelist/worker/os/check"
	AppendToWorkerWhitelistUrl   = "/whitelist/worker/os/add"
	DeleteFromWorkerWhitelistUrl = "/whitelist/worker/os/delete"
	DropWorkerWhitelistUrl       = "/whitelist/worker/os/drop"

	CheckPodWhitelistUrl    = "/whitelist/pod/image/check"
	AppendToPodWhitelistUrl = "/whitelist/pod/image/add"
	AppendFilesToImageUrl   = "/whitelist/pod/image/file/add"
	DeleteFilesFromImageUrl = "/whitelist/pod/image/file/delete"
	DropPodWhitelistUrl     = "/whitelist/pod/drop"

	CheckContainerRuntimeWhitelistUrl      = "/whitelist/container/runtime/check"
	AppendToContainerRuntimeWhitelistUrl   = "/whitelist/container/runtime/add"
	DeleteFromContainerRuntimeWhitelistUrl = "/whitelist/container/runtime/delete"
	DropContainerRuntimeWhitelistUrl       = "/whitelist/container/runtime/drop"
)

type Server struct {
	whitelistHost  string
	whitelistPort  int
	whitelistDbUri string

	tlsCertificate  *x509.Certificate
	workerWhitelist *mongo.Collection
	podWhitelist    *mongo.Collection

	containerRuntimeWhitelist *mongo.Collection
	router                    *gin.Engine
}

func (s *Server) Init(whitelistHost string, whitelistPort int, whitelistDbUri string, tlsCertificate *x509.Certificate) {
	s.whitelistHost = whitelistHost
	s.whitelistPort = whitelistPort
	s.whitelistDbUri = whitelistDbUri
	s.tlsCertificate = tlsCertificate
}

// initializeMongoDB connects to the MongoDB database and sets the workerWhitelist collection.
func (s *Server) initializeMongoDB() {
	clientOptions := options.Client().ApplyURI(s.whitelistDbUri)

	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()

	client, err := mongo.Connect(ctx, clientOptions)
	if err != nil {
		logger.Fatal("Failed to connect to MongoDB client: %v", err)
	}

	// Access the database and workerWhitelist collection
	s.workerWhitelist = client.Database(dbName).Collection(workerCollection)
	s.podWhitelist = client.Database(dbName).Collection(podCollection)
	s.containerRuntimeWhitelist = client.Database(dbName).Collection(containerRuntimeCollection)
	return
}

// checkWorkerWhitelist verifies if a given OS and digest match the stored worker whitelist.
func (s *Server) checkWorkerWhitelist(c *gin.Context) {
	var checkRequest *model.WorkerWhitelistCheckRequest
	if err := c.ShouldBindJSON(checkRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid request body"})
		return
	}

	// Query MongoDB for the document matching the requested OS name
	var osWhitelist model.OsWhitelist
	err := s.workerWhitelist.FindOne(context.TODO(), bson.M{"osName": checkRequest.OsName}).Decode(osWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "OS whitelist not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to query worker whitelist"})
		}
		return
	}

	// Check if the digest matches within the specified hash algorithm category
	digests, exists := osWhitelist.ValidDigests[strings.ToLower(checkRequest.HashAlg)]
	if !exists {
		c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "No digests found for the specified hash algorithm"})
		return
	}

	for _, digest := range digests {
		if digest == checkRequest.BootAggregate {
			c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "Boot Aggregate matches the stored whitelist"})
			return
		}
	}

	c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "Boot Aggregate does not match the stored whitelist"})
	return
}

// appendToWorkerWhitelist handles the addition of a new valid OsWhitelist.
func (s *Server) appendToWorkerWhitelist(c *gin.Context) {
	var newOsWhitelist *model.OsWhitelist

	// Bind JSON input to the OsWhitelist struct
	if err := c.ShouldBindJSON(newOsWhitelist); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid request body"})
		return
	}

	// Check if the OSName already exists in the WorkerWhitelist
	var existingOsWhitelist *model.OsWhitelist
	err := s.workerWhitelist.FindOne(context.TODO(), bson.M{"osName": newOsWhitelist.OSName}).Decode(existingOsWhitelist)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to query Worker whitelist"})
		return
	}

	if existingOsWhitelist.OSName == newOsWhitelist.OSName {
		c.JSON(http.StatusConflict, gin.H{"status": model.Error, "message": "OS whitelist already exists"})
		return
	}

	// Insert the new OS whitelist
	_, err = s.workerWhitelist.InsertOne(context.TODO(), newOsWhitelist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to append new valid OS list to Worker whitelist"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "OS whitelist added successfully"})
	return
}

// deleteFromWorkerWhitelist deletes a worker whitelist record based on the provided OSName.
func (s *Server) deleteFromWorkerWhitelist(c *gin.Context) {
	osName, err := url.QueryUnescape(c.Query("osName"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid osName"})
		return
	}
	// Attempt to delete the document with the matching OSName
	result, err := s.workerWhitelist.DeleteOne(context.TODO(), bson.M{"osName": osName})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to delete the worker whitelist record"})
		return
	}

	// Check if any document was deleted
	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "Worker whitelist record not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "Worker whitelist record deleted successfully"})
}

// dropWorkerWhitelist drops the workerWhitelist collection from the MongoDB database.
func (s *Server) dropWorkerWhitelist(c *gin.Context) {
	// Drop the workerWhitelist collection
	err := s.workerWhitelist.Drop(context.TODO())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to drop Worker whitelist"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "Worker whitelist dropped successfully"})
	return
}

// checkPodWhitelist verifies if the given pod's files match the stored whitelist for the pod's image.
func (s *Server) checkPodWhitelist(c *gin.Context) {
	var checkRequest *model.PodWhitelistCheckRequest
	if err := c.ShouldBindJSON(checkRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid request body"})
		return
	}

	// Query MongoDB for matching pod image
	var imageWhitelist *model.ImageWhitelist
	err := s.podWhitelist.FindOne(context.TODO(), bson.M{"imageName": checkRequest.PodImageName}).Decode(imageWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "Pod image not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to query Pod whitelist"})
		}
		return
	}

	if imageWhitelist.ImageDigest != checkRequest.PodImageDigest {
		c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "Provided Pod image digest does not match stored image digest"})
		return
	}

	// Iterate through the pod files to check if they match the stored whitelist
	for _, podFile := range checkRequest.PodFiles {
		found := false
		for _, validFile := range imageWhitelist.ValidFiles {
			// Check if the file paths match
			if podFile.FilePath == validFile.FilePath {
				digests, exists := validFile.ValidDigests[strings.ToLower(checkRequest.HashAlg)]
				if !exists {
					c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "No digests found for the specified hash algorithm"})
					return
				}

				// Check if the file hash matches any of the valid digests
				for _, digest := range digests {
					if digest == podFile.FileHash {
						found = true
						break
					}
				}
				if found {
					break // Move on to the next pod file once a match is found
				}
			}
		}

		// If no match is found for the current pod file
		if !found {
			c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "File hash does not match the stored whitelist"})
			return
		}
	}

	// If all pod files match
	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "All pod files match the stored whitelist"})
}

// appendNewImageToPodWhitelist adds a new ImageWhitelist with valid files to the pod whitelist if it doesn't exist
func (s *Server) appendImageToPodWhitelist(c *gin.Context) {
	var imageWhitelist *model.ImageWhitelist

	// Bind JSON input to the ImageWhitelist struct
	if err := c.ShouldBindJSON(imageWhitelist); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid request body"})
		return
	}

	// Query to check if the imageName already exists
	filter := bson.M{"imageName": imageWhitelist.ImageName}
	var existingImageWhitelist *model.ImageWhitelist
	err := s.podWhitelist.FindOne(context.TODO(), filter).Decode(existingImageWhitelist)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// If the image does not exist, insert it
			_, err := s.podWhitelist.InsertOne(context.TODO(), imageWhitelist)
			if err != nil {
				c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to append new image whitelist"})
				return
			}
			c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "New image whitelist added successfully"})
			return
		} else {
			// If any other error occurs during query
			c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to query Pod whitelist"})
			return
		}
	}

	// If the image already exists, return a conflict message
	c.JSON(http.StatusConflict, gin.H{"status": model.Error, "message": "Image whitelist already exists"})
}

// appendFilesToExistingImageWhitelistByImageName adds new valid files to an existing ImageWhitelist for the given imageName.
func (s *Server) appendFilesToImage(c *gin.Context) {
	var appendFilesRequest *model.AppendFilesToImageRequest
	// Bind JSON input to the list of new valid files
	if err := c.ShouldBindJSON(appendFilesRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid request body"})
		return
	}

	// Check if the image whitelist exists
	filter := bson.M{"imageName": appendFilesRequest.ImageName}
	update := bson.M{"$addToSet": bson.M{"validFiles": bson.M{"$each": appendFilesRequest.NewFiles}}}

	// Update the existing ImageWhitelist with new valid files
	_, err := s.podWhitelist.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to append files: no whitelist for Pod image:" + appendFilesRequest.ImageName})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "Files added to Pod image whitelist successfully"})
}

// deleteFileFromPodWhitelist deletes a file and its digests under a given imageName and filePath in the pod whitelist.
func (s *Server) deleteFileFromImage(c *gin.Context) {
	imageName, err := url.QueryUnescape(c.Query("imageName"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "Invalid imageName"})
		return
	}
	filePath, err := url.QueryUnescape(c.Query("filePath"))
	if err != nil {
		c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "Invalid filePath"})
		return
	}

	// Query MongoDB for the pod image whitelist by imageName
	filter := bson.M{"imageName": imageName}
	var imageWhitelist *model.ImageWhitelist
	err = s.podWhitelist.FindOne(context.TODO(), filter).Decode(imageWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "Pod image not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to query Pod whitelist"})
		}
		return
	}

	// Search for the file by filePath and remove it along with its digests
	var updatedValidFiles []model.PodFileWhitelist
	fileFound := false

	for _, validFile := range imageWhitelist.ValidFiles {
		if validFile.FilePath == filePath {
			fileFound = true
			// Skip adding this file to updatedValidFiles to effectively remove it
			continue
		}
		updatedValidFiles = append(updatedValidFiles, validFile)
	}

	if !fileFound {
		c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "File path not found in the whitelist"})
		return
	}

	// Update MongoDB with the modified whitelist (remove the file)
	update := bson.M{"$set": bson.M{"validFiles": updatedValidFiles}} // fixed the field name here
	_, err = s.podWhitelist.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to update Pod whitelist"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "File and associated digests removed from the whitelist"})
}

// dropPodWhitelist drops the podWhitelist collection from the MongoDB database.
func (s *Server) dropPodWhitelist(c *gin.Context) {
	// Drop the podWhitelist collection
	err := s.podWhitelist.Drop(context.TODO())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to drop Pod whitelist"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "Pod whitelist dropped successfully"})
	return
}

// checkContainerRuntimeWhitelist verifies if a given Container Runtime and digest match the stored Container Runtime whitelist.
func (s *Server) checkContainerRuntimeWhitelist(c *gin.Context) {
	var checkRequest *model.ContainerRuntimeCheckRequest
	if err := c.ShouldBindJSON(checkRequest); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid request body"})
		return
	}

	// Query MongoDB for the document matching the requested Container Runtime name
	var existingContainerRuntimeWhitelist *model.ContainerRuntimeWhitelist
	err := s.containerRuntimeWhitelist.FindOne(context.TODO(), bson.M{"containerRuntimeName": checkRequest.ContainerRuntimeName}).Decode(existingContainerRuntimeWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "Container Runtime whitelist not found"})
		} else {
			c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to query Container Runtime whitelist"})
		}
		return
	}

	// Iterate through the pod files to check if they match the stored whitelist
	for _, containerRuntimeDependency := range checkRequest.ContainerRuntimeDependencies {
		found := false
		for _, validFile := range existingContainerRuntimeWhitelist.ValidFiles {
			// Check if the file paths match
			if containerRuntimeDependency.FilePath == validFile.FilePath {
				digests, exists := validFile.ValidDigests[strings.ToLower(checkRequest.HashAlg)]
				if !exists {
					c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "No digests found for the specified hash algorithm"})
					return
				}

				// Check if the file hash matches any of the valid digests
				for _, digest := range digests {
					if digest == containerRuntimeDependency.FileHash {
						found = true
						break
					}
				}
				if found {
					break // Move on to the next container runtime dependency file once a match is found
				}
			}
		}

		// If no match is found for the current container dependency file
		if !found {
			c.JSON(http.StatusUnauthorized, gin.H{"status": model.Error, "message": "File hash does not match the stored whitelist"})
			return
		}
	}

	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "All Container Runtime depdencency files match the stored whitelist"})
	return
}

// appendToContainerRuntimeWhitelist handles the addition of a new valid ContainerRuntimeWhitelist.
func (s *Server) appendToContainerRuntimeWhitelist(c *gin.Context) {
	var newContainerRuntimeWhitelist *model.ContainerRuntimeWhitelist

	// Bind JSON input to the OsWhitelist struct
	if err := c.ShouldBindJSON(newContainerRuntimeWhitelist); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid request body"})
		return
	}

	// Check if the Container Runtime already exists in the Container Runtime whitelist
	var existingContainerRuntimeWhitelist *model.ContainerRuntimeWhitelist
	err := s.containerRuntimeWhitelist.FindOne(context.TODO(), bson.M{"containerRuntimeName": newContainerRuntimeWhitelist.ContainerRuntimeName}).Decode(existingContainerRuntimeWhitelist)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to query Container Runtime whitelist"})
		return
	}

	if existingContainerRuntimeWhitelist.ContainerRuntimeName == newContainerRuntimeWhitelist.ContainerRuntimeName {
		c.JSON(http.StatusConflict, gin.H{"status": model.Error, "message": "Container Runtime whitelist already exists"})
		return
	}

	// Insert the new OS whitelist
	_, err = s.containerRuntimeWhitelist.InsertOne(context.TODO(), newContainerRuntimeWhitelist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to append new valid Container Runtime list to Container Runtime whitelist"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "Container Runtime whitelist added successfully"})
	return
}

// deleteFromContainerRuntimeWhitelist deletes a container runtime whitelist record based on the provided containerRuntimeName.
func (s *Server) deleteFromContainerRuntimeWhitelist(c *gin.Context) {
	containerRuntimeName, err := url.QueryUnescape(c.Query("containerRuntimeName"))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"status": model.Error, "message": "Invalid containerRuntimeName"})
		return
	}
	// Attempt to delete the document with the matching OSName
	result, err := s.containerRuntimeWhitelist.DeleteOne(context.TODO(), bson.M{"containerRuntimeName": containerRuntimeName})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to delete the Container Runtime whitelist record"})
		return
	}

	// Check if any document was deleted
	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, gin.H{"status": model.Error, "message": "Container Runtime whitelist record not found"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "Container Runtime whitelist record deleted successfully"})
}

// dropContainerRuntimeWhitelist drops the containerRuntimeWhitelist collection from the MongoDB database.
func (s *Server) dropContainerRuntimeWhitelist(c *gin.Context) {
	// Drop the workerWhitelist collection
	err := s.containerRuntimeWhitelist.Drop(context.TODO())
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"status": model.Error, "message": "Failed to drop Container Runtime whitelist"})
		return
	}
	c.JSON(http.StatusOK, gin.H{"status": model.Success, "message": "Container Runtime whitelist dropped successfully"})
	return
}

func (s *Server) Start() {
	// Initialize Gin router
	s.router = gin.Default()

	// Worker whitelist
	s.router.POST(CheckWorkerWhitelistUrl, s.checkWorkerWhitelist)
	s.router.POST(AppendToWorkerWhitelistUrl, s.appendToWorkerWhitelist)
	s.router.DELETE(DeleteFromWorkerWhitelistUrl, s.deleteFromWorkerWhitelist)
	s.router.DELETE(DropWorkerWhitelistUrl, s.dropWorkerWhitelist)

	// Pod whitelist
	s.router.POST(CheckPodWhitelistUrl, s.checkPodWhitelist)
	s.router.POST(AppendToPodWhitelistUrl, s.appendImageToPodWhitelist)
	s.router.POST(AppendFilesToImageUrl, s.appendFilesToImage)
	s.router.DELETE(DeleteFilesFromImageUrl, s.deleteFileFromImage)
	s.router.DELETE(DropPodWhitelistUrl, s.dropPodWhitelist)

	// Container Runtime whitelist
	s.router.POST(CheckContainerRuntimeWhitelistUrl, s.checkContainerRuntimeWhitelist)
	s.router.POST(AppendToContainerRuntimeWhitelistUrl, s.appendToContainerRuntimeWhitelist)
	s.router.DELETE(DeleteFromContainerRuntimeWhitelistUrl, s.deleteFromContainerRuntimeWhitelist)
	s.router.DELETE(DropContainerRuntimeWhitelistUrl, s.dropContainerRuntimeWhitelist)

	// Start the server
	if err := s.router.Run(":" + strconv.Itoa(s.whitelistPort)); err != nil {
		logger.Fatal("Failed to run the server: %v", err)
	}
}
