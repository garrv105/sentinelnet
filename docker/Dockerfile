FROM python:3.11-slim

LABEL maintainer="SentinelNet"
LABEL description="Adaptive Threat Detection & Automated Response Toolkit"

# Install system dependencies
RUN apt-get update && apt-get install -y \
    iptables \
    libpcap-dev \
    tcpdump \
    net-tools \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install Python dependencies
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application
COPY . .
RUN pip install -e .

# Create log and model directories
RUN mkdir -p logs models

EXPOSE 8000

# Default: show help (override with actual args in docker-compose)
ENTRYPOINT ["python", "-m", "sentinelnet"]
CMD ["--help"]
