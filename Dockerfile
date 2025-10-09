# --------------------------------------------------
# Stage 1: Build & Obfuscate Go binary with garble
# --------------------------------------------------
FROM golang:1.25 AS builder

# Install garble
RUN go install mvdan.cc/garble@latest

# Create and switch to the app directory
WORKDIR /app

# Initialize a new Go module and copy the source
RUN go mod init example.com/myapp
COPY main.go .

# Download dependencies
RUN go mod tidy

# Set up environment for obfuscation and Windows cross-compilation
ENV GOOS=windows \
    GOARCH=386 \
    CGO_ENABLED=0 \
    GOGARBLE=1

# Use garble to build the binary with symbol obfuscation
RUN $(go env GOPATH)/bin/garble build -ldflags="-s -w -H=windowsgui" -o myServiceAgent.exe main.go

# --------------------------------------------------
# Stage 2: Minimal final image (optional)
# --------------------------------------------------
FROM scratch AS final

WORKDIR /app

# Copy obfuscated executable from builder
COPY --from=builder /app/myServiceAgent.exe /myServiceAgent.exe

CMD ["/myServiceAgent.exe"]
