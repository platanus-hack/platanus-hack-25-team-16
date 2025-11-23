# Dockerfile for Django ISO 27001 MVP
FROM python:3.12-slim

# Set environment variables
ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

# Install system dependencies
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    build-essential \
    libmagic1 \
    && rm -rf /var/lib/apt/lists/*

# Install uv for fast dependency management
RUN pip install --no-cache-dir uv

# Set work directory
WORKDIR /app

# Copy only dependency files first (for better layer caching)
COPY pyproject.toml uv.lock ./

# Install Python dependencies
RUN uv pip install --system .

# Copy the rest of the project files
COPY . .

# Create directories for static files and crypto keys
RUN mkdir -p /app/staticfiles /var/lib/crypto_keys && \
    chmod 700 /var/lib/crypto_keys

# The environment variable DJANGO_CRYPTO_FIELDS_KEY_PATH should be set at runtime using Docker's -e flag or a secrets manager.

# Collect static files (only once, during build)
RUN python manage.py collectstatic --noinput

# Expose port
EXPOSE 8000

# Start server (migrations + gunicorn for production)
# For development, you can override this with: docker run ... python manage.py runserver 0.0.0.0:8000
CMD ["sh", "-c", "python manage.py migrate && gunicorn app.wsgi:application --bind 0.0.0.0:8000 --workers 3"]
