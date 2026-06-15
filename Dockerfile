# ============================================================
# CyTrack — Production Dockerfile
# Multi-stage build: builder + final runtime image
# ============================================================

# --- Stage 1: Builder ---
FROM python:3.12-slim AS builder

WORKDIR /app

# Install system dependencies needed to compile Python packages
RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    libpq-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first (layer caching)
COPY requirements.txt .

# Install Python dependencies into a virtual environment
RUN python -m venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"
RUN pip install --upgrade pip && \
    pip install --no-cache-dir -r requirements.txt

# --- Stage 2: Final Runtime Image ---
FROM python:3.12-slim

# Security: run as non-root user
RUN groupadd -r cytrack && useradd -r -g cytrack cytrack

WORKDIR /app

# Install runtime system libraries only
RUN apt-get update && apt-get install -y --no-install-recommends \
    libpq5 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Copy virtual environment from builder
COPY --from=builder /opt/venv /opt/venv
ENV PATH="/opt/venv/bin:$PATH"

# Copy application code
COPY --chown=cytrack:cytrack . .

# Create required directories
RUN mkdir -p /app/staticfiles /app/media /app/logs && \
    chown -R cytrack:cytrack /app

# Copy and set up entrypoint
COPY --chown=cytrack:cytrack docker/entrypoint.sh /entrypoint.sh
RUN chmod +x /entrypoint.sh

# Switch to non-root user
USER cytrack

# Environment variables
ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    DJANGO_ENV=production \
    PORT=8000

EXPOSE 8000

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=30s --retries=3 \
    CMD curl -f http://localhost:8000/health/ping/ || exit 1

ENTRYPOINT ["/entrypoint.sh"]
CMD ["web"]
