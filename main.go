package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/smithy-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/h2non/filetype"
	"github.com/joho/godotenv"
	_ "golang.org/x/image/webp"
)

const (
	maxFileSize      = 10 * 1024 * 1024  // 10 MB for images
	maxVideoSize     = 500 * 1024 * 1024 // 500 MB for videos
)

var (
	r2AccountID       = getEnv("R2_ACCOUNT_ID", "")
	r2AccessKeyID     = getEnv("R2_ACCESS_KEY_ID", "")
	r2SecretAccessKey = getEnv("R2_SECRET_ACCESS_KEY", "")
	r2BucketName      = getEnv("R2_BUCKET_NAME", "")
	r2PublicURL       = getEnv("R2_PUBLIC_URL", "")
	s3Client          *s3.Client

	b2AccountID       = getEnv("B2_ACCOUNT_ID", "")
	b2AccessKeyID     = getEnv("B2_ACCESS_KEY_ID", "")
	b2SecretAccessKey = getEnv("B2_SECRET_ACCESS_KEY", "")
	b2BucketName      = getEnv("B2_BUCKET_NAME", "")
	b2Endpoint        = getEnv("B2_ENDPOINT", "")
	b2PublicURL       = getEnv("B2_PUBLIC_URL", "")
	b2Client          *s3.Client
)

// R2Uploader struct holds the S3 client
type R2Uploader struct {
	Client *s3.Client
}

// NewR2Uploader creates a new R2 uploader
func NewR2Uploader() (*R2Uploader, error) {
	r2Resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: fmt.Sprintf("https://%s.r2.cloudflarestorage.com", r2AccountID),
		}, nil
	})

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(r2Resolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(r2AccessKeyID, r2SecretAccessKey, "")),
		config.WithRegion("auto"),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &R2Uploader{
		Client: s3.NewFromConfig(cfg),
	}, nil
}

// NewB2Uploader creates a new B2 uploader
func NewB2Uploader() (*R2Uploader, error) {
	b2Resolver := aws.EndpointResolverWithOptionsFunc(func(service, region string, options ...interface{}) (aws.Endpoint, error) {
		return aws.Endpoint{
			URL: b2Endpoint,
		}, nil
	})

	cfg, err := config.LoadDefaultConfig(context.TODO(),
		config.WithEndpointResolverWithOptions(b2Resolver),
		config.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(b2AccessKeyID, b2SecretAccessKey, "")),
		config.WithRegion("us-east-1"), // B2 requires a region, often us-east-1 is fine or specific region
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load B2 AWS config: %w", err)
	}

	return &R2Uploader{
		Client: s3.NewFromConfig(cfg),
	}, nil
}

func main() {
	// Load .env file
	if err := godotenv.Load(); err != nil {
		log.Println("No .env file found, using environment variables")
	}

	// Re-evaluate variables after loading .env
	r2AccountID = getEnv("R2_ACCOUNT_ID", "")
	r2AccessKeyID = getEnv("R2_ACCESS_KEY_ID", "")
	r2SecretAccessKey = getEnv("R2_SECRET_ACCESS_KEY", "")
	r2BucketName = getEnv("R2_BUCKET_NAME", "")
	r2PublicURL = getEnv("R2_PUBLIC_URL", "")

	b2AccountID = getEnv("B2_ACCOUNT_ID", "")
	b2AccessKeyID = getEnv("B2_ACCESS_KEY_ID", "")
	b2SecretAccessKey = getEnv("B2_SECRET_ACCESS_KEY", "")
	b2BucketName = getEnv("B2_BUCKET_NAME", "")
	b2Endpoint = getEnv("B2_ENDPOINT", "")
	b2PublicURL = getEnv("B2_PUBLIC_URL", "")

	// Check for required environment variables
	if r2AccountID == "" || r2AccessKeyID == "" || r2SecretAccessKey == "" || r2BucketName == "" || r2PublicURL == "" {
		log.Fatal("Missing required environment variables for R2")
	}
	if b2AccountID == "" || b2AccessKeyID == "" || b2SecretAccessKey == "" || b2BucketName == "" || b2Endpoint == "" || b2PublicURL == "" {
		log.Println("Warning: Missing required environment variables for B2. Video uploads will not work.")
	}

	uploader, err := NewR2Uploader()
	if err != nil {
		log.Fatalf("Failed to create R2 uploader: %v", err)
	}
	s3Client = uploader.Client

	if b2AccessKeyID != "" {
		b2Uploader, err := NewB2Uploader()
		if err != nil {
			log.Fatalf("Failed to create B2 uploader: %v", err)
		}
		b2Client = b2Uploader.Client
	}

	router := gin.Default()

	// CORS middleware
    config := cors.DefaultConfig()
    config.AllowOrigins = []string{
        "http://localhost:3000",
        "https://chanomhub.online",
        "https://chanomhub.com",
        "https://www.chanomhub.online",
        "https://www.chanomhub.com",
    }
    config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
    config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
    config.AllowCredentials = true
    router.Use(cors.New(config))

	router.GET("/health", healthCheckHandler)
	router.POST("/upload", uploadHandler)

	log.Println("Server started at http://localhost:8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

func healthCheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func uploadHandler(c *gin.Context) {
	// Try getting 'image' first, then 'file'
	file, header, err := c.Request.FormFile("image")
	if err != nil {
		file, header, err = c.Request.FormFile("file")
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "File is required (use key 'image' or 'file')"})
			return
		}
	}
	defer file.Close()

	// 1. Initial Type Detection to determine max size
	// We read the first 261 bytes to detect type
	head := make([]byte, 261)
	if _, err := file.Read(head); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file header"})
		return
	}
	// Seek back to start
	if _, err := file.Seek(0, 0); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to reset file pointer"})
		return
	}

	kind, _ := filetype.Match(head)
	if kind == filetype.Unknown {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown file type"})
		return
	}

	isVideo := false
	if strings.HasPrefix(kind.MIME.Value, "video/") {
		isVideo = true
	} else if !strings.HasPrefix(kind.MIME.Value, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Only images and videos are allowed."})
		return
	}

	// 2. Validate Size
	limit := maxFileSize
	if isVideo {
		limit = maxVideoSize
	}

	if header.Size > int64(limit) {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("File size exceeds the limit of %d MB", limit/1024/1024)})
		return
	}

	// 3. Read file into buffer
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file buffer"})
		return
	}
	fileBytes := buf.Bytes()

	// 4. Detailed Validation
	ext := strings.ToLower(filepath.Ext(header.Filename))
	
	if isVideo {
		// Valid video extensions
		allowedVideo := map[string]bool{".mp4": true, ".webm": true, ".mov": true, ".mkv": true, ".avi": true}
		if !allowedVideo[ext] {
			// Try to infer extension from MIME if missing or wrong
			// But for now, just validate known extensions
			// Relaxing check slightly or use what user sent if match
		}
	} else {
		// Image Security Check: Decode Config
		fileReader := bytes.NewReader(fileBytes)
		_, _, err = image.DecodeConfig(fileReader)
		if err != nil {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid image file: not a valid image or format is corrupted"})
			return
		}
	}

	// Double check MIME
	expectedContentType := getContentType(ext)
	// Some browsers/systems might send different extensions for same mime, so we key loose here
	// But ensure it matches our server side detection
	if kind.MIME.Value != expectedContentType {
		// Special handling cause extension vs mime map might not be perfect
		// c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("File mismatch: %s vs %s", ext, kind.MIME.Value)})
		// Let's just trust filetype detection for Content-Type
	}
	contentType := kind.MIME.Value

	// 5. Deduplication & Upload
	hash := sha256.Sum256(fileBytes)
	hashString := hex.EncodeToString(hash[:])
	newFileName := fmt.Sprintf("%s%s", hashString, ext)

	// Determine Target Config
	var targetClient *s3.Client
	var targetBucket string
	var targetPublicURL string

	if isVideo {
		if b2Client == nil {
			c.JSON(http.StatusServiceUnavailable, gin.H{"error": "Video upload service is not configured"})
			return
		}
		targetClient = b2Client
		targetBucket = b2BucketName
		targetPublicURL = b2PublicURL
	} else {
		targetClient = s3Client
		targetBucket = r2BucketName
		targetPublicURL = r2PublicURL
	}

	// Check existence
	_, err = targetClient.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(targetBucket),
		Key:    aws.String(newFileName),
	})

	if err == nil {
		c.JSON(http.StatusOK, gin.H{"message": "File already exists", "url": newFileName, "full_url": fmt.Sprintf("%s/%s", targetPublicURL, newFileName)})
		return
	}

	var apiError smithy.APIError
	if !errors.As(err, &apiError) || apiError.ErrorCode() != "NotFound" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check for file existence"})
		return
	}

	// Upload
	_, err = targetClient.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(targetBucket),
		Key:         aws.String(newFileName),
		Body:        bytes.NewReader(fileBytes),
		ContentType: aws.String(contentType),
		ACL:         "public-read", // B2 supports S3 ACLs usually
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload file to storage"})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully", "url": newFileName, "full_url": fmt.Sprintf("%s/%s", targetPublicURL, newFileName)})
}

func getContentType(ext string) string {
	switch ext {
	// Images
	case ".jpeg", ".jpg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
	case ".avif":
		return "image/avif"
	// Videos
	case ".mp4":
		return "video/mp4"
	case ".webm":
		return "video/webm"
	case ".mov":
		return "video/quicktime"
	case ".avi":
		return "video/x-msvideo"
	default:
		return "application/octet-stream"
	}
}

// getEnv gets an environment variable or returns a default value
func getEnv(key, fallback string) string {
	if value, ok := os.LookupEnv(key); ok {
		return value
	}
	return fallback
}
