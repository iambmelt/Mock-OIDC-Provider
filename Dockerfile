# Mock OIDC Provider - Multi-stage Dockerfile
# Stage 1: Builder - Install dependencies and prepare for runtime
FROM python:3.12-slim as builder

# Set working directory
WORKDIR /build

# Install build dependencies needed for cryptography
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy package files needed for installation
COPY pyproject.toml .
COPY mock_oidc/ ./mock_oidc/

# Install the package into a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip setuptools wheel && \
    pip install .

# Stage 2: Runtime - Minimal image with only runtime dependencies
FROM python:3.12-slim

# Create non-root user for security
RUN useradd -m -u 1000 -s /sbin/nologin app

# Set working directory
WORKDIR /app

# Install only runtime dependencies (OpenSSL runtime libs, not dev tools)
RUN apt-get update && apt-get install -y --no-install-recommends \
    libssl3 \
    ca-certificates \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder stage (package is installed inside it)
COPY --from=builder /opt/venv /opt/venv

# Set environment variables
ENV PATH="/opt/venv/bin:$PATH" \
    PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1

# Switch to non-root user
USER app

# Expose port 4567 for the OIDC provider
EXPOSE 4567

# Health check - container orchestration will use this to monitor health
# Checks /health endpoint every 10 seconds, allows 3 failures before marking unhealthy
HEALTHCHECK --interval=10s --timeout=3s --start-period=5s --retries=3 \
    CMD python -c "\
import urllib.request, ssl, sys; \
ctx = ssl.create_default_context(); \
ctx.check_hostname = False; \
ctx.verify_mode = ssl.CERT_NONE; \
try: \
    r = urllib.request.urlopen('https://localhost:4567/health', timeout=2, context=ctx); \
    sys.exit(0 if r.status == 200 else 1) \
except Exception as e: \
    print(f'Health check failed: {e}'); \
    sys.exit(1)"

# Default entrypoint and command
# ENTRYPOINT defines the main executable (the mock-oidc command)
# CMD provides default arguments (--ssl-quickboot for easy testing)
ENTRYPOINT ["mock-oidc"]
CMD ["--ssl-quickboot"]
