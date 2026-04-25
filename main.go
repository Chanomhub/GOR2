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
	"regexp"
	"strings"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go"
	"github.com/gin-contrib/cors"
	"github.com/gin-gonic/gin"
	"github.com/golang-jwt/jwt/v5"
	"github.com/h2non/filetype"
	"github.com/joho/godotenv"
	_ "golang.org/x/image/webp"
)

const (
	maxFileSize      = 10 * 1024 * 1024  // 10 MB for images
	maxVideoSize     = 500 * 1024 * 1024 // 500 MB for videos
)

var (
	// jwtSecret is required for security
	jwtSecret         = getEnv("JWT_SECRET", "")

	// --- Domain Mapping Documentation ---
	// r2PublicURL (Images/Media)       -> cdn.chanomhub.com
	// r2StoragePublicURL (Game Files)  -> storage.chanomhub.com
	// ------------------------------------

	r2AccountID       = getEnv("R2_ACCOUNT_ID", "")
	r2AccessKeyID     = getEnv("R2_ACCESS_KEY_ID", "")
	r2SecretAccessKey = getEnv("R2_SECRET_ACCESS_KEY", "")
	r2BucketName      = getEnv("R2_BUCKET_NAME", "")
	r2PublicURL       = getEnv("R2_PUBLIC_URL", "")

	// New storage bucket for games
	r2StorageBucketName = getEnv("R2_STORAGE_BUCKET_NAME", "")
	r2StoragePublicURL  = getEnv("R2_STORAGE_PUBLIC_URL", "")

	s3Client          *s3.Client

	b2AccountID       = getEnv("B2_ACCOUNT_ID", "")
	b2AccessKeyID     = getEnv("B2_ACCESS_KEY_ID", "")
	b2SecretAccessKey = getEnv("B2_SECRET_ACCESS_KEY", "")
	b2BucketName      = getEnv("B2_BUCKET_NAME", "")
	b2Endpoint        = getEnv("B2_ENDPOINT", "")
	b2PublicURL       = getEnv("B2_PUBLIC_URL", "")
	b2Client          *s3.Client
)

// S3Config helper struct
type S3Config struct {
	Client    *s3.Client
	Bucket    string
	PublicURL string
}

func getS3Config(targetBucketType string, isVideo bool) (*S3Config, error) {
	var targetClient *s3.Client
	var targetBucket string
	var targetPublicURL string

	if targetBucketType == "storage" {
		if r2StorageBucketName == "" {
			return nil, errors.New("storage bucket is not configured")
		}
		targetClient = s3Client
		targetBucket = r2StorageBucketName
		targetPublicURL = r2StoragePublicURL
	} else if isVideo {
		if b2Client == nil {
			return nil, errors.New("video upload service is not configured")
		}
		targetClient = b2Client
		targetBucket = b2BucketName
		targetPublicURL = b2PublicURL
	} else {
		targetClient = s3Client
		targetBucket = r2BucketName
		targetPublicURL = r2PublicURL
	}

	return &S3Config{
		Client:    targetClient,
		Bucket:    targetBucket,
		PublicURL: targetPublicURL,
	}, nil
}

func generateObjectKey(pathPrefix, gameSlug, fileName, shortHash string) string {
	now := time.Now()
	year := now.Year()
	month := int(now.Month())

	// No mandatory 'public' prefix anymore. Starts from root unless pathPrefix is given.
	prefix := ""
	if pathPrefix != "" {
		prefix = strings.Trim(pathPrefix, "/")
	}

	re := regexp.MustCompile(`[^a-zA-Z0-9.\-_]`)
	safeName := re.ReplaceAllString(fileName, "_")

	// Final Structure: [prefix/][game-slug/]year/month/[hash/]safe_name
	var parts []string
	
	if prefix != "" {
		parts = append(parts, prefix)
	}
	
	if gameSlug != "" && !isGenericSlug(gameSlug) {
		parts = append(parts, gameSlug)
	}
	
	parts = append(parts, fmt.Sprintf("%d/%02d", year, month))
	
	if shortHash != "" {
		parts = append(parts, shortHash)
	} else {
		parts = append(parts, fmt.Sprintf("%d", time.Now().UnixNano()))
	}
	
	parts = append(parts, safeName)

	return strings.Join(parts, "/")
}

func isGenericSlug(slug string) bool {
	lower := strings.ToLower(slug)
	return lower == "misc" || lower == "unknown" || lower == "pending" || lower == "unnamed-game"
}

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
	jwtSecret = getEnv("JWT_SECRET", "")
	r2AccountID = getEnv("R2_ACCOUNT_ID", "")
	r2AccessKeyID = getEnv("R2_ACCESS_KEY_ID", "")
	r2SecretAccessKey = getEnv("R2_SECRET_ACCESS_KEY", "")
	r2BucketName = getEnv("R2_BUCKET_NAME", "")
	r2PublicURL = getEnv("R2_PUBLIC_URL", "")

	r2StorageBucketName = getEnv("R2_STORAGE_BUCKET_NAME", "")
	r2StoragePublicURL = getEnv("R2_STORAGE_PUBLIC_URL", "")

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

	if jwtSecret == "" {
		log.Fatal("JWT_SECRET is required for security")
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
		"http://localhost:3001",
		"https://chanomhub.com",
		"https://www.chanomhub.com",
	}
	config.AllowMethods = []string{"GET", "POST", "PUT", "DELETE", "OPTIONS"}
	config.AllowHeaders = []string{"Origin", "Content-Type", "Accept", "Authorization"}
	config.AllowCredentials = true
	router.Use(cors.New(config))

	router.GET("/health", healthCheckHandler)

	// Protected routes
	authorized := router.Group("/")
	authorized.Use(JWTMiddleware())
	{
		authorized.POST("/upload", uploadHandler)
		// Chunked/Multipart Upload Routes
		authorized.POST("/upload/initiate", initiateMultipartUploadHandler)
		authorized.POST("/upload/part", uploadPartHandler)
		authorized.POST("/upload/complete", completeMultipartUploadHandler)
		authorized.POST("/upload/abort", abortMultipartUploadHandler)
	}

	log.Println("Server started at http://localhost:8080")
	if err := router.Run(":8080"); err != nil {
		log.Fatalf("Failed to run server: %v", err)
	}
}

func JWTMiddleware() gin.HandlerFunc {
	return func(c *gin.Context) {
		authHeader := c.GetHeader("Authorization")
		if authHeader == "" {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header is required"})
			return
		}

		// Handle potential double Bearer prefix or weird formatting from backend/some clients
		// Examples: "Bearer Bearer eyJ...", "Bearer Authorization: Bearer eyJ...", "Bearer Bearer Bearer eyJ..."
		authHeader = strings.TrimSpace(authHeader)
		for {
			if strings.HasPrefix(authHeader, "Bearer ") {
				authHeader = strings.TrimPrefix(authHeader, "Bearer ")
			} else if strings.HasPrefix(authHeader, "Authorization: ") {
				authHeader = strings.TrimPrefix(authHeader, "Authorization: ")
			} else {
				break
			}
			authHeader = strings.TrimSpace(authHeader)
		}
		// Put it back to a single "Bearer {token}" for the next split logic
		authHeader = "Bearer " + authHeader

		parts := strings.SplitN(authHeader, " ", 2)
		if !(len(parts) == 2 && parts[0] == "Bearer") {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Authorization header must be in 'Bearer {token}' format"})
			return
		}

		tokenString := parts[1]
		token, err := jwt.Parse(tokenString, func(token *jwt.Token) (interface{}, error) {
			// Validate the signing method
			if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
				return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
			}
			return []byte(jwtSecret), nil
		})

		if err != nil || !token.Valid {
			c.AbortWithStatusJSON(http.StatusUnauthorized, gin.H{"error": "Invalid or expired token"})
			return
		}

		// Optionally set user information in context
		if claims, ok := token.Claims.(jwt.MapClaims); ok {
			c.Set("user_id", claims["sub"])
			c.Set("username", claims["username"])
		}

		c.Next()
	}
}

func healthCheckHandler(c *gin.Context) {
	c.JSON(http.StatusOK, gin.H{"status": "ok"})
}

func uploadHandler(c *gin.Context) {
	// 0. Determine Target Bucket and Path
	targetBucketType := c.Query("bucket") // e.g. "storage"
	pathPrefix := c.Query("path")         // e.g. "public" or "premium"

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
	// Relaxed type checking for storage bucket
	if targetBucketType != "storage" {
		if kind == filetype.Unknown {
			c.JSON(http.StatusBadRequest, gin.H{"error": "Unknown file type"})
			return
		}
	}

	isVideo := false
	if kind != filetype.Unknown && strings.HasPrefix(kind.MIME.Value, "video/") {
		isVideo = true
	} else if targetBucketType != "storage" && !strings.HasPrefix(kind.MIME.Value, "image/") {
		c.JSON(http.StatusBadRequest, gin.H{"error": "Invalid file type. Only images and videos are allowed."})
		return
	}

	// 2. Validate Size
	limit := maxFileSize
	if isVideo {
		limit = maxVideoSize
	}
	if targetBucketType == "storage" {
		// Allow larger files for game storage
		limit = 1000 * 1024 * 1024 // 1 GB limit for storage
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

	if targetBucketType != "storage" {
		if isVideo {
			// Valid video extensions
			allowedVideo := map[string]bool{".mp4": true, ".webm": true, ".mov": true, ".mkv": true, ".avi": true}
			if !allowedVideo[ext] {
				// We still allow it if filetype detected it as video
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
	}

	// Double check MIME
	contentType := kind.MIME.Value
	if contentType == "" || contentType == "application/octet-stream" {
		contentType = getContentType(ext)
	}

	// 5. Deduplication & Upload
	gameSlug := c.Query("game")
	if targetBucketType == "storage" {
		if gameSlug == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "game slug is required for storage bucket"})
			return
		}
		// Block generic slugs
		genericSlugs := map[string]bool{"misc": true, "unknown": true, "pending": true, "unnamed-game": true}
		if genericSlugs[strings.ToLower(gameSlug)] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "generic game slugs are not allowed for storage bucket"})
			return
		}
	}

	hash := sha256.Sum256(fileBytes)
	hashString := hex.EncodeToString(hash[:])
	shortHash := hashString[:8]

	objectKey := generateObjectKey(pathPrefix, gameSlug, header.Filename, shortHash)

	// Determine Target Config
	cfg, err := getS3Config(targetBucketType, isVideo)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	// Check existence
	_, err = cfg.Client.HeadObject(context.TODO(), &s3.HeadObjectInput{
		Bucket: aws.String(cfg.Bucket),
		Key:    aws.String(objectKey),
	})

	if err == nil {
		c.JSON(http.StatusOK, gin.H{
			"message":  "File already exists",
			"url":      objectKey,
			"filename": header.Filename,
			"full_url": fmt.Sprintf("%s/%s", cfg.PublicURL, objectKey),
		})
		return
	}

	var apiError smithy.APIError
	if !errors.As(err, &apiError) || apiError.ErrorCode() != "NotFound" {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to check for file existence"})
		return
	}

	// Upload
	_, err = cfg.Client.PutObject(context.TODO(), &s3.PutObjectInput{
		Bucket:      aws.String(cfg.Bucket),
		Key:         aws.String(objectKey),
		Body:        bytes.NewReader(fileBytes),
		ContentType: aws.String(contentType),
		ACL:         "public-read", // B2 supports S3 ACLs usually
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to upload file to storage"})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "File uploaded successfully",
		"url":      objectKey,
		"filename": header.Filename,
		"full_url": fmt.Sprintf("%s/%s", cfg.PublicURL, objectKey),
	})
}

// Multipart Upload Handlers

func initiateMultipartUploadHandler(c *gin.Context) {
	targetBucketType := c.Query("bucket")
	pathPrefix := c.Query("path")
	gameSlug := c.Query("game")
	filename := c.Query("filename")
	contentType := c.Query("contentType")

	if targetBucketType == "storage" {
		if gameSlug == "" {
			c.JSON(http.StatusBadRequest, gin.H{"error": "game slug is required for storage bucket"})
			return
		}
		// Block generic slugs
		genericSlugs := map[string]bool{"misc": true, "unknown": true, "pending": true, "unnamed-game": true}
		if genericSlugs[strings.ToLower(gameSlug)] {
			c.JSON(http.StatusBadRequest, gin.H{"error": "generic game slugs are not allowed for storage bucket"})
			return
		}
	}

	if filename == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "filename query parameter is required"})
		return
	}

	ext := strings.ToLower(filepath.Ext(filename))
	isVideo := false
	if strings.HasPrefix(contentType, "video/") || strings.Contains(".mp4.webm.mov.mkv.avi", ext) {
		isVideo = true
	}

	if contentType == "" {
		contentType = getContentType(ext)
	}

	cfg, err := getS3Config(targetBucketType, isVideo)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	objectKey := generateObjectKey(pathPrefix, gameSlug, filename, "")

	output, err := cfg.Client.CreateMultipartUpload(context.TODO(), &s3.CreateMultipartUploadInput{
		Bucket:      aws.String(cfg.Bucket),
		Key:         aws.String(objectKey),
		ContentType: aws.String(contentType),
		ACL:         "public-read",
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to initiate multipart upload: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"uploadId": *output.UploadId,
		"key":      *output.Key,
		"bucket":   cfg.Bucket,
		"isVideo":  isVideo,
	})
}

func uploadPartHandler(c *gin.Context) {
	uploadId := c.Query("uploadId")
	key := c.Query("key")
	partNumberStr := c.Query("partNumber")
	bucket := c.Query("bucket")
	isVideoStr := c.Query("isVideo")

	if uploadId == "" || key == "" || partNumberStr == "" || bucket == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uploadId, key, partNumber, and bucket are required"})
		return
	}

	var partNumber int32
	fmt.Sscanf(partNumberStr, "%d", &partNumber)

	isVideo := isVideoStr == "true"
	// We need the client but we already have the bucket.
	// We use bucket type to decide which client (R2 or B2).
	// For simplicity, we can try to guess from bucket name or just pass bucketType.
	targetBucketType := c.Query("bucketType")
	cfg, err := getS3Config(targetBucketType, isVideo)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	// Read body
	body, err := io.ReadAll(c.Request.Body)
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": "Failed to read part data"})
		return
	}

	output, err := cfg.Client.UploadPart(context.TODO(), &s3.UploadPartInput{
		Bucket:     aws.String(bucket),
		Key:        aws.String(key),
		UploadId:   aws.String(uploadId),
		PartNumber: &partNumber,
		Body:       bytes.NewReader(body),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to upload part: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"etag": *output.ETag,
	})
}

type LocalCompletedPart struct {
	ETag       string `json:"etag" binding:"required"`
	PartNumber int32  `json:"partNumber" binding:"required"`
}

type CompleteMultipartRequest struct {
	UploadId   string               `json:"uploadId" binding:"required"`
	Key        string               `json:"key" binding:"required"`
	Bucket     string               `json:"bucket" binding:"required"`
	Parts      []LocalCompletedPart `json:"parts" binding:"required"`
	IsVideo    bool                 `json:"isVideo"`
	BucketType string               `json:"bucketType"`
}

func completeMultipartUploadHandler(c *gin.Context) {
	var req CompleteMultipartRequest
	if err := c.ShouldBindJSON(&req); err != nil {
		c.JSON(http.StatusBadRequest, gin.H{"error": err.Error()})
		return
	}

	cfg, err := getS3Config(req.BucketType, req.IsVideo)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	// Convert local parts to AWS SDK types
	completedParts := make([]types.CompletedPart, len(req.Parts))
	for i, p := range req.Parts {
		completedParts[i] = types.CompletedPart{
			ETag:       aws.String(p.ETag),
			PartNumber: aws.Int32(p.PartNumber),
		}
	}

	_, err = cfg.Client.CompleteMultipartUpload(context.TODO(), &s3.CompleteMultipartUploadInput{
		Bucket:   aws.String(req.Bucket),
		Key:      aws.String(req.Key),
		UploadId: aws.String(req.UploadId),
		MultipartUpload: &types.CompletedMultipartUpload{
			Parts: completedParts,
		},
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to complete multipart upload: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{
		"message":  "Upload completed successfully",
		"key":      req.Key,
		"url":      req.Key,
		"full_url": fmt.Sprintf("%s/%s", cfg.PublicURL, req.Key),
	})
}

func abortMultipartUploadHandler(c *gin.Context) {
	uploadId := c.Query("uploadId")
	key := c.Query("key")
	bucket := c.Query("bucket")
	isVideo := c.Query("isVideo") == "true"
	bucketType := c.Query("bucketType")

	if uploadId == "" || key == "" || bucket == "" {
		c.JSON(http.StatusBadRequest, gin.H{"error": "uploadId, key, and bucket are required"})
		return
	}

	cfg, err := getS3Config(bucketType, isVideo)
	if err != nil {
		c.JSON(http.StatusServiceUnavailable, gin.H{"error": err.Error()})
		return
	}

	_, err = cfg.Client.AbortMultipartUpload(context.TODO(), &s3.AbortMultipartUploadInput{
		Bucket:   aws.String(bucket),
		Key:      aws.String(key),
		UploadId: aws.String(uploadId),
	})
	if err != nil {
		c.JSON(http.StatusInternalServerError, gin.H{"error": fmt.Sprintf("Failed to abort multipart upload: %v", err)})
		return
	}

	c.JSON(http.StatusOK, gin.H{"message": "Upload aborted successfully"})
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
