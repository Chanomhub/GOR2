# Stage 1: Builder
# This stage builds the Go application.
FROM golang:1.25.1 AS builder

# Set the Current Working Directory inside the container
WORKDIR /app

# Copy go mod and sum files
COPY go.mod go.sum ./

# Download all dependencies. Dependencies will be cached if the go.mod and go.sum files are not changed
RUN go mod download

# Copy the source code into the container
COPY . .

# Build the Go app
# -o /app/main: specifies the output file name
# CGO_ENABLED=0: builds a statically linked binary
RUN CGO_ENABLED=0 go build -o /app/main .

# Stage 2: Final
# This stage creates the final, small, and secure image.
FROM alpine:latest

WORKDIR /app

# Copy the pre-built binary file from the builder stage
COPY --from=builder /app/main .

# Expose port 8080 to the outside world
EXPOSE 8080

# Command to run the executable
CMD ["/app/main"]
