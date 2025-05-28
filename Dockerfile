FROM python:3.13-alpine AS base

# Install build dependencies
RUN apk add --no-cache gcc musl-dev libffi-dev

WORKDIR /app

# Copy and install requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY . .

# Set common environment variables
ENV PYTHONUNBUFFERED=1
ENV PYTHONDONTWRITEBYTECODE=1
ENV PYTHONPATH=/app
ENV AM_I_IN_A_DOCKER_CONTAINER=Yes

# Create non-root user
RUN addgroup -g 1001 -S appgroup && \
    adduser -S appuser -u 1001 -G appgroup && \
    chown -R appuser:appgroup /app

USER appuser

# STDIO variant
FROM base AS stdio
ENV TRANSPORT_TYPE=stdio
ENTRYPOINT ["python", "main.py"]

# SSE variant
FROM base AS sse
ENV TRANSPORT_TYPE=sse
EXPOSE 3000
ENTRYPOINT ["python", "main.py", "--sse", "--host=0.0.0.0", "--port=3000", "--iunderstandtherisks"]