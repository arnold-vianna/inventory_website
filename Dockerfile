# Use an official Python runtime as the base image
FROM python:3.13-slim

# Set the working directory in the container
WORKDIR /app

# Copy the requirements file into the container
COPY requirements.txt .

# Install dependencies
RUN pip install --no-cache-dir -r requirements.txt

# Copy the rest of the application code into the container
COPY . .

# Ensure the static/images directory exists and set permissions
RUN mkdir -p static/images && \
    chown -R 1000:1000 /app && \
    chmod -R 755 /app

# Run as a non-root user for security
USER 1000:1000

# Expose port 5049
EXPOSE 5049

# Run the app with Gunicorn
CMD ["gunicorn", "--workers", "4", "--bind", "0.0.0.0:5049", "app:app"]