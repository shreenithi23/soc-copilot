# Multi-stage build for SOC Copilot (React frontend bundle + FastAPI backend)

FROM node:20-alpine AS frontend-builder
WORKDIR /build
COPY package.json package-lock.json ./
RUN npm ci
COPY src/ ./src/
COPY static/ ./static/
RUN npm run build

FROM python:3.11-slim
WORKDIR /app

# Install system dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    curl \
    sqlite3 \
    && rm -rf /var/lib/apt/lists/*

# Install Python requirements
COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

# Copy application code
COPY app/ ./app/
COPY static/ ./static/
COPY tests/ ./tests/
COPY run.sh .env* ./

# Copy built frontend bundle from builder stage
COPY --from=frontend-builder /build/static/js/bundle.js ./static/js/bundle.js

# Ensure data directory exists
RUN mkdir -p /app/data

EXPOSE 8000

ENV HOST=0.0.0.0
ENV PORT=8000
ENV REDIS_HOST=redis
ENV REDIS_PORT=6379
ENV DATABASE_PATH=/app/data/soc_copilot.db

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
