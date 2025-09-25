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
	"github.com/gin-gonic/gin"
	"github.com/gin-contrib/cors"
	"github.com/joho/godotenv"
	"github.com/meblum/turnstile"
	_ "golang.org/x/image/webp"
)

const (
	maxFileSize = 10 * 1024 * 1024 // 10 MB
)

var (
	r2AccountID        = getEnv("R2_ACCOUNT_ID", "")
	r2AccessKeyID      = getEnv("R2_ACCESS_KEY_ID", "")
	r2SecretAccessKey  = getEnv("R2_SECRET_ACCESS_KEY", "")
	r2BucketName       = getEnv("R2_BUCKET_NAME", "")
	r2PublicURL        = getEnv("R2_PUBLIC_URL", "")
	turnstileSecretKey = getEnv("TURNSTILE_SECRET_KEY", "")
	s3Client           *s3.Client
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
	turnstileSecretKey = getEnv("TURNSTILE_SECRET_KEY", "")

	// Check for required environment variables
	if r2AccountID == "" || r2AccessKeyID == "" || r2SecretAccessKey == "" || r2BucketName == "" || r2PublicURL == "" {
		log.Fatal("Missing required environment variables (R2_ACCOUNT_ID, R2_ACCESS_KEY_ID, R2_SECRET_ACCESS_KEY, R2_BUCKET_NAME, R2_PUBLIC_URL)")
	}

	uploader, err := NewR2Uploader()
	if err != nil {
		log.Fatalf("Failed to create R2 uploader: %v", err)
	}
	s3Client = uploader.Client

	router := gin.Default()

	// CORS middleware
	config := cors.DefaultConfig()
	config.AllowOrigins = []string{"http://localhost:3000"}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
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
	// Turnstile verification
	token := c.PostForm("cf-turnstile-response")
	verifier := turnstile.NewVerifier(turnstileSecretKey, nil)
	verified, err := verifier.Verify(token, c.ClientIP(), "")
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Turnstile verification failed"})
		return
	}
	if !verified.Success {
		c.JSON(http.StatusForbidden, gin.H{"error": "Turnstile verification failed"})
		return
	}

	file, header, err := c.Request.FormFile("image")
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Image file is required"})
		return
	}
	defer file.Close()

	// Validate file size
	if header.Size > maxFileSize {
		c.JSON(http.StatusBadRequest, gin.H{"error": fmt.Sprintf("File size exceeds the limit of %d MB", maxFileSize/1024/1024)})
		return
	}

	// Read file into a buffer for multiple reads (validation, hashing, uploading)
	buf := bytes.NewBuffer(nil)
	if _, err := io.Copy(buf, file); err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read file buffer"})
		return
	}

	// Security Check: Validate that it's a real image file by decoding its config
	allowedExts := map[string]bool{".jpeg": true, ".jpg": true, ".png": true, ".gif": true, ".webp": true}
	ext := strings.ToLower(filepath.Ext(header.Filename))
	if !allowedExts[ext] {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Allowed types: JPEG, PNG, GIF, WebP"})
		return
	}

	_, _, err = image.DecodeConfig(bytes.NewReader(buf.Bytes()))
	if err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid image file: not a valid image or format is corrupted"})
		return
	}

	// Deduplication Check: Calculate SHA-256 hash of the file content
	hash := sha256.Sum256(buf.Bytes())
	hashString := hex.EncodeToString(hash[:])
	newFileName := fmt.Sprintf("%s%s", hashString, ext)

	// Check if file already exists in R2
	_, err = s3Client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(r2BucketName),
		Key:    aws.String(newFileName),
	})

	// If err is nil, object exists. If err is not nil, check if it's a NotFound error.
	if err == nil {
		// Object already exists, return its URL
		publicURL := fmt.Sprintf("%s/%s", r2PublicURL, newFileName)
		c.JSON(http.StatusOK, gin.H{"message": "File already exists", "url": publicURL})
		return
	}

	var apiError smithy.APIError
	if !errors.As(err, &apiError) || apiError.ErrorCode() != "NotFound" {
		// An actual error occurred during HeadObject
		log.Printf("Failed to check for object in R2: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check for file existence"})
		return
	}

	// Get the correct content type based on file extension
	contentType := getContentType(ext)

	// Upload to R2 since it does not exist
	_, err = s3Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(r2BucketName),
		Key:         aws.String(newFileName),
		Body:        bytes.NewReader(buf.Bytes()),
		ContentType: aws.String(contentType), // เพิ่มบรรทัดนี้
		ACL:         "public-read",
	})
	if err != nil {
		log.Printf("Failed to upload to R2: %v", err)
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload file"})
		return
	}

	// Construct public URL
	publicURL := fmt.Sprintf("%s/%s", r2PublicURL, newFileName)

	c.JSON(http.StatusOK, gin.H{"message": "File uploaded successfully", "url": publicURL})
}

func getContentType(ext string) string {
	switch ext {
	case ".jpeg", ".jpg":
		return "image/jpeg"
	case ".png":
		return "image/png"
	case ".gif":
		return "image/gif"
	case ".webp":
		return "image/webp"
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
