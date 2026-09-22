# syntax=docker/dockerfile:1

# ---------------------------------------------------------------------------
# Stage 1: build the Go binary
# ---------------------------------------------------------------------------
FROM golang:1.24-bookworm AS builder

RUN apt-get update && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download

COPY . .
RUN CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build \
    -trimpath \
    -ldflags="-s -w" \
    -o /mobiscope \
    ./cmd/mobiscope

# ---------------------------------------------------------------------------
# Stage 2: runtime with the full external toolchain
#
# eclipse-temurin on Ubuntu (glibc) rather than Alpine: semgrep does not
# support musl, and apktool/jadx need a JRE anyway.
# ---------------------------------------------------------------------------
FROM eclipse-temurin:21-jre-jammy AS runtime

ARG GITLEAKS_VERSION=8.24.3
ARG APKTOOL_VERSION=2.11.1
ARG JADX_VERSION=1.5.1

RUN apt-get update && apt-get install -y --no-install-recommends \
        ca-certificates \
        curl \
        python3 \
        python3-pip \
        unzip \
    && rm -rf /var/lib/apt/lists/*

# gitleaks — secret detection (static binary)
RUN curl -fsSL "https://github.com/gitleaks/gitleaks/releases/download/v${GITLEAKS_VERSION}/gitleaks_${GITLEAKS_VERSION}_linux_x64.tar.gz" \
        | tar -xz -C /usr/local/bin gitleaks \
    && chmod +x /usr/local/bin/gitleaks \
    && gitleaks version

# apktool — Android resource decoding (JAR + wrapper)
RUN curl -fsSL -o /usr/local/bin/apktool.jar \
        "https://github.com/iBotPeaches/Apktool/releases/download/v${APKTOOL_VERSION}/apktool_${APKTOOL_VERSION}.jar" \
    && printf '#!/bin/sh\nexec java -jar /usr/local/bin/apktool.jar "$@"\n' > /usr/local/bin/apktool \
    && chmod +x /usr/local/bin/apktool \
    && apktool --version

# jadx — Android bytecode decompilation
RUN curl -fsSL "https://github.com/skylot/jadx/releases/download/v${JADX_VERSION}/jadx-${JADX_VERSION}.zip" -o /tmp/jadx.zip \
    && unzip -q /tmp/jadx.zip -d /opt/jadx \
    && ln -sf /opt/jadx/bin/jadx /usr/local/bin/jadx \
    && rm /tmp/jadx.zip \
    && jadx --version

# semgrep — pattern scanning (SARIF)
RUN pip3 install --no-cache-dir "semgrep==1.127.1" \
    && semgrep --version

COPY --from=builder /mobiscope /usr/local/bin/mobiscope
COPY --from=builder /src/rules /app/rules

WORKDIR /app

# Non-root user: analysis artifacts and extracted sources stay unprivileged.
RUN useradd --create-home --uid 10001 mobiscope \
    && mkdir -p /app/targets \
    && chown -R mobiscope:mobiscope /app
USER mobiscope

EXPOSE 8080

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -fsS http://127.0.0.1:8080/healthz || exit 1

ENTRYPOINT ["mobiscope"]
# 0.0.0.0 inside a container is fine: publish the port deliberately from
# docker-compose (loopback by default) or via docker run -p.
CMD ["serve", "--addr", "0.0.0.0:8080"]
