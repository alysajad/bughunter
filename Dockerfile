# Use an official Python runtime as a parent image
FROM python:3.11-slim

# Set the working directory in the container
WORKDIR /app

# Install system dependencies (needed for xhtml2pdf/WeasyPrint usually)
# xhtml2pdf may need cairo/pango if updated, but basic version might be fine.
# Adding basic tools just in case.
RUN apt-get update && apt-get install -y \
    build-essential \
    libssl-dev \
    libffi-dev \
    python3-dev \
    libjpeg-dev \
    zlib1g-dev \
    fonts-liberation \
    fontconfig \
    pkg-config \
    libcairo2-dev \
    libpango1.0-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy the requirements file into the container
COPY requirements.txt .

# Install any needed packages specified in requirements.txt
RUN pip install --no-cache-dir -r requirements.txt

# Install Gunicorn for production serving
RUN pip install gunicorn

# Copy the rest of the application code
COPY . .

# Expose port 5000 (Flask default)
EXPOSE 5000

# Define environment variable
ENV FLASK_APP=app.py
ENV PYTHONUNBUFFERED=1

# Run app.py using Gunicorn
# Timeout set to 300s (5 mins) to allow for longer scans on free tiers
CMD ["gunicorn", "--bind", "0.0.0.0:5000", "--timeout", "300", "app:app"]
