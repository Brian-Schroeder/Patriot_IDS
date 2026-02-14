FROM python:3.11-slim

# Set working directory
WORKDIR /app

# Install system dependencies for packet capture
RUN apt-get update && apt-get install -y \
    libpcap-dev \
    tcpdump \
    && rm -rf /var/lib/apt/lists/*

# Copy requirements first for caching
COPY requirements.txt.
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY..

# Create non-root user
RUN useradd -m -u 1000 idsuser

# Create log directory
RUN mkdir -p /app/logs && chown -R idsuser:idsuser /app

# Environment variables
ENV IDS_HOST=0.0.0.0
ENV IDS_PORT=5000
ENV NETWORK_INTERFACE=eth0
ENV PYTHONUNBUFFERED=1

# Note: For packet capture, container needs NET_ADMIN capability
# Run with: docker run --cap-add=NET_ADMIN --network=host

# Expose port
EXPOSE 5000

# Run as root for packet capture (or use capabilities)
# USER idsuser

# Health check
HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD curl -f http://localhost:5000/api/v1/health || exit 1

# Start application
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--workers", "4", "--threads", "2", "app:app"]