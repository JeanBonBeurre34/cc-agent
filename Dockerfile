# Use the official Go image as a builder stage.
FROM golang:1.17 AS builder

# Create and change to the app directory.
WORKDIR /app

# Initialize a new module and copy the Go source.
# Replace "example.com/myapp" with your module name or a placeholder.
RUN go mod init example.com/myapp
COPY main.go .

# Fetch dependencies.
# Using go mod tidy to add missing and remove unused modules.
RUN go mod tidy

# Build the application to a Windows executable using cross-compilation.
# If you don't need a Windows executable, remove the ENV lines.
ENV GOOS=windows
ENV GOARCH=386
RUN go build  -ldflags="-s -w -H=windowsgui" -o myServiceAgent.exe main.go

# Use a scratch image to keep the final image minimal.
# Note: Scratch is an empty container and won't run Windows executables.
# This stage is used to illustrate how to package the executable.
# For running, you'll need to extract the executable or use a Windows base image.
FROM scratch AS final

WORKDIR /app

# Copy the compiled executable from the builder stage.
COPY --from=builder /app/myServiceAgent.exe /myServiceAgent.exe

CMD ["/myServiceAgent.exe"]
