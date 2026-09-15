FROM python:3.11-slim

WORKDIR /app

# Install system dependencies for OpenCV, image decoding, and healthcheck
RUN apt-get update && apt-get install -y --no-install-recommends \
    libglib2.0-0 \
    libgl1 \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Create unprivileged application user
RUN useradd -u 1001 -m -s /bin/bash appuser

COPY ai_engine/requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application source and set ownership
COPY ai_engine/ ./ai_engine/
RUN chown -R appuser:appuser /app

USER appuser

EXPOSE 8000

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
  CMD curl -f http://127.0.0.1:8000/api/health || exit 1

CMD ["python", "-m", "uvicorn", "ai_engine.main:app", "--host", "0.0.0.0", "--port", "8000"]
