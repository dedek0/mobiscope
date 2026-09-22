# Stage 1: Build the Go binary
FROM golang:1.24-alpine AS builder

RUN apk add --no-cache git ca-certificates

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /mobiscope \
    ./cmd/mobiscope

# Stage 2: Runtime (minimal image)
FROM eclipse-temurin:21-jre-alpine AS runtime

# apktool and jadx need Java.
# gitleaks and semgrep binaries would be added here in production.
RUN apk add --no-cache curl ca-certificates

COPY --from=builder /mobiscope /usr/local/bin/mobiscope
COPY --from=builder /src/rules /app/rules

WORKDIR /app

EXPOSE 8080

ENTRYPOINT ["mobiscope"]
CMD ["serve", "--addr", "0.0.0.0:8080"]