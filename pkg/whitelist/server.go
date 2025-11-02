package whitelist

import (
	"context"
	"crypto"
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

type ImageWhitelist struct {
	Name       string                `json:"name" bson:"name"`
	Digest     string                `json:"digest" bson:"digest"`
	ValidFiles []model.FileWhitelist `json:"validFiles" json:"validFiles"`
}

// OsWhitelist represents the structure of our stored document in MongoDB.
// It categorizes valid digests by hash algorithm.
type OsWhitelist struct {
	Name         string                   `json:"name" bson:"name"`
	ValidDigests map[crypto.Hash][]string `json:"validDigests" bson:"validDigests"` // Hash algorithm as the key
}

type ContainerDependencyWhitelist struct {
	FilePath     string                   `json:"filePath" bson:"filePath"`
	ValidDigests map[crypto.Hash][]string `json:"validDigests" bson:"validDigests"` // Hash algorithm as the key
}

type ContainerRuntimeWhitelist struct {
	Name       string                         `json:"name" bson:"name"`
	ValidFiles []ContainerDependencyWhitelist `json:"validFiles" json:"validFiles"`
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
	var checkRequest model.WorkerWhitelistCheckRequest
	if err := c.ShouldBindJSON(&checkRequest); err != nil {
		c.JSON(http.StatusBadRequest, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Message: "Invalid request body",
				Status:  model.Error,
			}})
		return
	}

	var erroredEntries model.ErroredEntries
	// Query MongoDB for the document matching the requested OS name
	var osWhitelist OsWhitelist
	err := s.workerWhitelist.FindOne(context.TODO(), bson.M{"name": checkRequest.OsName}).Decode(&osWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			absentEntry := model.AbsentEntry{
				Id:         checkRequest.OsName,
				HashAlg:    checkRequest.HashAlg,
				ActualHash: checkRequest.BootAggregate,
			}
			erroredEntries.Absent = append(erroredEntries.Absent, absentEntry)
			c.JSON(http.StatusNotFound, model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Status:  model.Error,
					Message: "OS whitelist not found",
				},
				ErroredEntries: erroredEntries,
			})
		} else {
			c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Status:  model.Error,
					Message: "Failed to query worker whitelist",
				}})
		}
		return
	}

	// Check if the digest matches within the specified hash algorithm category
	validDigests, exists := osWhitelist.ValidDigests[checkRequest.HashAlg]
	if !exists {
		absentEntry := model.AbsentEntry{
			Id:         checkRequest.OsName,
			HashAlg:    checkRequest.HashAlg,
			ActualHash: checkRequest.BootAggregate,
		}
		erroredEntries.Absent = append(erroredEntries.Absent, absentEntry)
		c.JSON(http.StatusNotFound, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "No digests found for the specified hash algorithm",
			}})
		return
	}

	matching := false
	for _, digest := range validDigests {
		if digest == checkRequest.BootAggregate {
			matching = true
			break
		}
	}

	if !matching {
		mismatchedEntry := model.MismatchingEntry{
			Id:           checkRequest.OsName,
			HashAlg:      checkRequest.HashAlg,
			ActualHash:   checkRequest.BootAggregate,
			ExpectedHash: validDigests,
		}
		erroredEntries.Mismatching = append(erroredEntries.Mismatching, mismatchedEntry)
		c.JSON(http.StatusUnauthorized, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Boot Aggregate does not match the stored whitelist",
			},
			ErroredEntries: erroredEntries,
		})
		return
	}

	c.JSON(http.StatusOK, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Success,
			Message: "Boot Aggregate matches the stored whitelist",
		}})
}

// appendToWorkerWhitelist handles the addition of a new valid OsWhitelist.
func (s *Server) appendToWorkerWhitelist(c *gin.Context) {
	var newOsWhitelist OsWhitelist

	// Bind JSON input to the OsWhitelist struct
	if err := c.ShouldBindJSON(&newOsWhitelist); err != nil {
		c.JSON(http.StatusBadRequest, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Invalid request body",
			}})
		return
	}

	// Check if the OSName already exists in the WorkerWhitelist
	var existingOsWhitelist OsWhitelist
	err := s.workerWhitelist.FindOne(context.TODO(), bson.M{"name": newOsWhitelist.Name}).Decode(&existingOsWhitelist)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to query Worker whitelist",
			}})
		return
	}

	if existingOsWhitelist.Name == newOsWhitelist.Name {
		c.JSON(http.StatusConflict, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "OS whitelist already exists",
			},
		})
		return
	}

	// Insert the new OS whitelist
	_, err = s.workerWhitelist.InsertOne(context.TODO(), newOsWhitelist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to append new valid OS list to Worker whitelist",
			}})
		return
	}

	c.JSON(http.StatusOK, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Success,
			Message: "OS whitelist added successfully",
		}})
	return
}

// deleteFromWorkerWhitelist deletes a worker whitelist record based on the provided OSName.
func (s *Server) deleteFromWorkerWhitelist(c *gin.Context) {
	osName, err := url.QueryUnescape(c.Query("osName"))
	if err != nil {
		c.JSON(http.StatusBadRequest, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Invalid os Name",
			}})
		return
	}
	// Attempt to delete the document with the matching OSName
	result, err := s.workerWhitelist.DeleteOne(context.TODO(), bson.M{"name": osName})
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to delete the worker whitelist record",
			}})
		return
	}

	// Check if any document was deleted
	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Worker whitelist record not found",
			}})
		return
	}

	c.JSON(http.StatusOK, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Success,
			Message: "Worker whitelist record deleted successfully",
		}})
}

// dropWorkerWhitelist drops the workerWhitelist collection from the MongoDB database.
func (s *Server) dropWorkerWhitelist(c *gin.Context) {
	// Drop the workerWhitelist collection
	err := s.workerWhitelist.Drop(context.TODO())
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to drop Worker whitelist",
			}})
		return
	}
	c.JSON(http.StatusOK, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Success,
			Message: "Worker whitelist dropped successfully",
		}})
	return
}

// checkPodWhitelist verifies if the given pod's files match the stored whitelist for the pod's image.
func (s *Server) checkPodWhitelist(c *gin.Context) {
	var checkRequest model.PodWhitelistCheckRequest
	if err := c.ShouldBindJSON(&checkRequest); err != nil {
		c.JSON(http.StatusBadRequest,
			model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Message: "Invalid request body",
					Status:  model.Error,
				}})
		return
	}

	var erroredEntries model.ErroredEntries
	// Query for matching pod image
	var imageWhitelist ImageWhitelist
	err := s.podWhitelist.FindOne(context.TODO(), bson.M{"name": checkRequest.ImageName}).Decode(&imageWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			absentEntry := model.AbsentEntry{
				Id:         checkRequest.ImageName,
				ActualHash: checkRequest.ImageDigest,
			}
			erroredEntries.Absent = append(erroredEntries.Absent, absentEntry)
			c.JSON(http.StatusNotFound, model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Status:  model.Error,
					Message: "Pod image not found",
				},
				ErroredEntries: erroredEntries,
			})
		} else {
			c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Status:  model.Error,
					Message: "Failed to query Pod whitelist",
				}})
		}
		return
	}

	if imageWhitelist.Digest != checkRequest.ImageDigest {
		mismatchedEntry := model.MismatchingEntry{
			Id:           checkRequest.ImageName,
			ActualHash:   checkRequest.ImageDigest,
			ExpectedHash: []string{imageWhitelist.Digest},
		}
		erroredEntries.Mismatching = append(erroredEntries.Mismatching, mismatchedEntry)
		c.JSON(http.StatusUnauthorized, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Provided Pod image digest does not match stored image digest",
			},
			ErroredEntries: erroredEntries,
		})
		return
	}

	for _, validFile := range imageWhitelist.ValidFiles {
		found := false
		for _, podFile := range checkRequest.Files {
			if validFile.FilePath == podFile.FilePath {
				found = true
				break
			}
		}

		if !found {
			notRunEntry := model.NotRunEntry{
				Id:           validFile.FilePath,
				HashAlg:      checkRequest.HashAlg,
				ExpectedHash: validFile.ValidDigests[checkRequest.HashAlg],
			}
			erroredEntries.NotRun = append(erroredEntries.NotRun, notRunEntry)
		}
	}

	// Iterate through the pod files to check if they match the stored whitelist
	for _, podFile := range checkRequest.Files {
		found := false
		exists := false
		matching := false
		var validDigests []string

		for _, validFile := range imageWhitelist.ValidFiles {
			// Check if the file paths match
			if podFile.FilePath == validFile.FilePath {
				found = true
				validDigests, exists = validFile.ValidDigests[checkRequest.HashAlg]

				if !exists {
					absentEntry := model.AbsentEntry{
						Id:         podFile.FilePath,
						HashAlg:    checkRequest.HashAlg,
						ActualHash: podFile.FileHash,
					}
					erroredEntries.Absent = append(erroredEntries.Absent, absentEntry)
					break
				}

				// Check if the file hash matches any of the valid digests
				for _, digest := range validDigests {
					if digest == podFile.FileHash {
						matching = true
						break
					}
				}

				if !matching {
					mismatchedEntry := model.MismatchingEntry{
						Id:           podFile.FilePath,
						HashAlg:      checkRequest.HashAlg,
						ActualHash:   podFile.FileHash,
						ExpectedHash: validDigests,
					}
					erroredEntries.Mismatching = append(erroredEntries.Mismatching, mismatchedEntry)
				}
			}
		}

		if !found {
			absentEntry := model.AbsentEntry{
				Id:         podFile.FilePath,
				HashAlg:    checkRequest.HashAlg,
				ActualHash: podFile.FileHash,
			}
			erroredEntries.Absent = append(erroredEntries.Absent, absentEntry)
		}
	}

	// If no match is found for the current pod file
	if len(erroredEntries.Absent) > 0 || len(erroredEntries.NotRun) > 0 || len(erroredEntries.Mismatching) > 0 {
		c.JSON(http.StatusUnauthorized, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "file hash does not match the stored whitelist",
			},
			ErroredEntries: erroredEntries})
	} else {
		c.JSON(http.StatusOK, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Success,
				Message: "All pod files match the stored whitelist",
			}})
	}
}

// appendNewImageToPodWhitelist adds a new ImageWhitelist with valid files to the pod whitelist if it doesn't exist
func (s *Server) appendImageToPodWhitelist(c *gin.Context) {
	var imageWhitelist ImageWhitelist
	// Bind JSON input to the ImageWhitelist struct
	if err := c.ShouldBindJSON(&imageWhitelist); err != nil {
		c.JSON(http.StatusBadRequest, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Invalid request body",
			}})
		return
	}

	// Query to check if the imageName already exists
	filter := bson.M{"name": imageWhitelist.Name}
	var existingImageWhitelist ImageWhitelist
	err := s.podWhitelist.FindOne(context.TODO(), filter).Decode(&existingImageWhitelist)

	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			// If the image does not exist, insert it
			_, err := s.podWhitelist.InsertOne(context.TODO(), imageWhitelist)
			if err != nil {
				c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
					SimpleResponse: model.SimpleResponse{
						Status:  model.Error,
						Message: "Failed to append new image whitelist",
					}})
				return
			}
			c.JSON(http.StatusOK, model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Status:  model.Success,
					Message: "New image whitelist added successfully",
				}})
			return
		} else {
			// If any other error occurs during query
			c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Status:  model.Error,
					Message: "Failed to query Pod whitelist",
				}})
			return
		}
	}

	// If the image already exists, return a conflict message
	c.JSON(http.StatusConflict, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Error,
			Message: "Image whitelist already exists",
		}})
}

// appendFilesToExistingImageWhitelistByImageName adds new valid files to an existing ImageWhitelist for the given imageName.
func (s *Server) appendFilesToImage(c *gin.Context) {
	var appendFilesRequest model.AppendFilesToImageRequest
	// Bind JSON input to the list of new valid files
	if err := c.ShouldBindJSON(&appendFilesRequest); err != nil {
		c.JSON(http.StatusBadRequest, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Invalid request body",
			}})
		return
	}

	// Check if the image whitelist exists
	filter := bson.M{"name": appendFilesRequest.ImageName}
	update := bson.M{"$addToSet": bson.M{"validFiles": bson.M{"$each": appendFilesRequest.Files}}}

	// Update the existing ImageWhitelist with new valid files
	_, err := s.podWhitelist.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to append files: no whitelist for Pod image:" + appendFilesRequest.ImageName,
			}})
		return
	}

	c.JSON(http.StatusOK, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Success,
			Message: "Files added to Pod image whitelist successfully",
		}})
}

// deleteFileFromPodWhitelist deletes a file and its digests under a given imageName and filePath in the pod whitelist.
func (s *Server) deleteFileFromImage(c *gin.Context) {
	imageName, err := url.QueryUnescape(c.Query("imageName"))
	if err != nil {
		c.JSON(http.StatusNotFound, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Invalid imageName",
			}})
		return
	}
	filePath, err := url.QueryUnescape(c.Query("filePath"))
	if err != nil {
		c.JSON(http.StatusNotFound, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Invalid filePath",
			}})
		return
	}

	// Query MongoDB for the pod image whitelist by imageName
	filter := bson.M{"name": imageName}
	var imageWhitelist ImageWhitelist
	err = s.podWhitelist.FindOne(context.TODO(), filter).Decode(&imageWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			c.JSON(http.StatusNotFound, model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Status:  model.Error,
					Message: "Pod image not found",
				}})
		} else {
			c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Status:  model.Error,
					Message: "Failed to query Pod whitelist",
				}})
		}
		return
	}

	// Search for the file by filePath and remove it along with its digests
	var updatedValidFiles []model.FileWhitelist
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
		c.JSON(http.StatusNotFound, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "file path not found in the whitelist",
			}})
		return
	}

	// Update MongoDB with the modified whitelist (remove the file)
	update := bson.M{"$set": bson.M{"validFiles": updatedValidFiles}} // fixed the field name here
	_, err = s.podWhitelist.UpdateOne(context.TODO(), filter, update)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to update Pod whitelist",
			}})
		return
	}

	c.JSON(http.StatusOK, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Success,
			Message: "file and associated digests removed from the whitelist",
		}})
}

// dropPodWhitelist drops the podWhitelist collection from the MongoDB database.
func (s *Server) dropPodWhitelist(c *gin.Context) {
	// Drop the podWhitelist collection
	err := s.podWhitelist.Drop(context.TODO())
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to drop Pod whitelist",
			}})
		return
	}
	c.JSON(http.StatusOK, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Success,
			Message: "Pod whitelist dropped successfully",
		}})
	return
}

// checkContainerRuntimeWhitelist verifies if a given Container Runtime and digest match the stored Container Runtime whitelist.
func (s *Server) checkContainerRuntimeWhitelist(c *gin.Context) {
	var checkRequest model.ContainerRuntimeCheckRequest
	if err := c.ShouldBindJSON(&checkRequest); err != nil {
		c.JSON(http.StatusBadRequest, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Invalid request body",
			}})
		return
	}

	var erroredEntries model.ErroredEntries
	// Query MongoDB for the document matching the requested Container Runtime name
	var existingContainerRuntimeWhitelist ContainerRuntimeWhitelist
	err := s.containerRuntimeWhitelist.FindOne(context.TODO(), bson.M{"name": checkRequest.Name}).Decode(&existingContainerRuntimeWhitelist)
	if err != nil {
		if errors.Is(err, mongo.ErrNoDocuments) {
			absentEntry := model.AbsentEntry{
				Id:      checkRequest.Name,
				HashAlg: checkRequest.HashAlg,
			}
			erroredEntries.Absent = append(erroredEntries.Absent, absentEntry)
			c.JSON(http.StatusNotFound, model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Status:  model.Error,
					Message: "Container Runtime whitelist not found",
				},
				ErroredEntries: erroredEntries,
			})
		} else {
			c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
				SimpleResponse: model.SimpleResponse{
					Status:  model.Error,
					Message: "Failed to query Container Runtime whitelist",
				}})
		}
		return
	}

	for _, validFile := range existingContainerRuntimeWhitelist.ValidFiles {
		found := false
		for _, containerRuntimeDependency := range checkRequest.Dependencies {
			if validFile.FilePath == containerRuntimeDependency.FilePath {
				found = true
				break
			}
		}

		if !found {
			notRunEntry := model.NotRunEntry{
				Id:           validFile.FilePath,
				HashAlg:      checkRequest.HashAlg,
				ExpectedHash: validFile.ValidDigests[checkRequest.HashAlg],
			}
			erroredEntries.NotRun = append(erroredEntries.NotRun, notRunEntry)
		}
	}

	// Iterate through the pod files to check if they match the stored whitelist
	for _, containerRuntimeDependency := range checkRequest.Dependencies {
		found := false
		matching := false
		exists := false
		var validDigests []string

		for _, validFile := range existingContainerRuntimeWhitelist.ValidFiles {
			// Check if the file paths match
			if containerRuntimeDependency.FilePath == validFile.FilePath {
				found = true
				validDigests, exists = validFile.ValidDigests[checkRequest.HashAlg]

				if !exists {
					absentEntry := model.AbsentEntry{
						Id:         containerRuntimeDependency.FilePath,
						HashAlg:    checkRequest.HashAlg,
						ActualHash: containerRuntimeDependency.FileHash,
					}
					erroredEntries.Absent = append(erroredEntries.Absent, absentEntry)
					break
				}

				// Check if the file hash matches any of the valid digests
				for _, digest := range validDigests {
					if digest == containerRuntimeDependency.FileHash {
						matching = true
						break
					}
				}

				if !matching {
					mismatchedEntry := model.MismatchingEntry{
						Id:           containerRuntimeDependency.FilePath,
						HashAlg:      checkRequest.HashAlg,
						ActualHash:   containerRuntimeDependency.FileHash,
						ExpectedHash: validDigests,
					}
					erroredEntries.Mismatching = append(erroredEntries.Mismatching, mismatchedEntry)
				}
			}
		}

		if !found {
			absentEntry := model.AbsentEntry{
				Id:         containerRuntimeDependency.FilePath,
				HashAlg:    checkRequest.HashAlg,
				ActualHash: containerRuntimeDependency.FileHash,
			}
			erroredEntries.Absent = append(erroredEntries.Absent, absentEntry)
		}
	}

	if len(erroredEntries.Mismatching) > 0 || len(erroredEntries.Absent) > 0 || len(erroredEntries.NotRun) > 0 {
		c.JSON(http.StatusUnauthorized, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "file hash does not match the stored whitelist",
			},
			ErroredEntries: erroredEntries,
		})
	} else {
		c.JSON(http.StatusOK, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Success,
				Message: "All Container Runtime dependency files match the stored whitelist",
			}})
	}
}

// appendToContainerRuntimeWhitelist handles the addition of a new valid ContainerRuntimeWhitelist.
func (s *Server) appendToContainerRuntimeWhitelist(c *gin.Context) {
	var newContainerRuntimeWhitelist ContainerRuntimeWhitelist

	// Bind JSON input to the OsWhitelist struct
	if err := c.ShouldBindJSON(&newContainerRuntimeWhitelist); err != nil {
		c.JSON(http.StatusBadRequest, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Invalid request body",
			}})
		return
	}

	// Check if the Container Runtime already exists in the Container Runtime whitelist
	var existingContainerRuntimeWhitelist ContainerRuntimeWhitelist
	err := s.containerRuntimeWhitelist.FindOne(context.TODO(), bson.M{"name": newContainerRuntimeWhitelist.Name}).Decode(&existingContainerRuntimeWhitelist)
	if err != nil && !errors.Is(err, mongo.ErrNoDocuments) {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to query Container Runtime whitelist",
			}})
		return
	}

	if existingContainerRuntimeWhitelist.Name == newContainerRuntimeWhitelist.Name {
		c.JSON(http.StatusConflict, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Container Runtime whitelist already exists",
			}})
		return
	}

	// Insert the new OS whitelist
	_, err = s.containerRuntimeWhitelist.InsertOne(context.TODO(), newContainerRuntimeWhitelist)
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to append new valid Container Runtime list to Container Runtime whitelist",
			}})
		return
	}

	c.JSON(http.StatusOK, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Success,
			Message: "Container Runtime whitelist added successfully",
		}})
	return
}

// deleteFromContainerRuntimeWhitelist deletes a container runtime whitelist record based on the provided containerRuntimeName.
func (s *Server) deleteFromContainerRuntimeWhitelist(c *gin.Context) {
	containerRuntimeName, err := url.QueryUnescape(c.Query("containerRuntimeName"))
	if err != nil {
		c.JSON(http.StatusBadRequest, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Invalid containerRuntimeName",
			}})
		return
	}
	// Attempt to delete the document with the matching OSName
	result, err := s.containerRuntimeWhitelist.DeleteOne(context.TODO(), bson.M{"name": containerRuntimeName})
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to delete the Container Runtime whitelist record",
			}})
		return
	}

	// Check if any document was deleted
	if result.DeletedCount == 0 {
		c.JSON(http.StatusNotFound, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Container Runtime whitelist record not found",
			}})
		return
	}

	c.JSON(http.StatusOK, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Success,
			Message: "Container Runtime whitelist record deleted successfully",
		}})
}

// dropContainerRuntimeWhitelist drops the containerRuntimeWhitelist collection from the MongoDB database.
func (s *Server) dropContainerRuntimeWhitelist(c *gin.Context) {
	// Drop the workerWhitelist collection
	err := s.containerRuntimeWhitelist.Drop(context.TODO())
	if err != nil {
		c.JSON(http.StatusInternalServerError, model.WhitelistResponse{
			SimpleResponse: model.SimpleResponse{
				Status:  model.Error,
				Message: "Failed to drop Container Runtime whitelist",
			}})
		return
	}
	c.JSON(http.StatusOK, model.WhitelistResponse{
		SimpleResponse: model.SimpleResponse{
			Status:  model.Success,
			Message: "Container Runtime whitelist dropped successfully",
		}})
	return
}

func (s *Server) Start() {
	s.initializeMongoDB()
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
