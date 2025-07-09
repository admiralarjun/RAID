FROM python:3.11-slim

RUN apt-get update && apt-get install -y --no-install-recommends \
    wkhtmltopdf \
 && rm -rf /var/lib/apt/lists/*

RUN apt-get update && apt-get install -y fonts-dejavu-core

WORKDIR /app


# Install dependencies
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

# Copy project code
COPY . .

# Expose port 8000 for dev server
EXPOSE 8000