#!/bin/bash

# Script to automate running the inventory app
# Assumes the script is run from the project directory containing app.py, inventory.db, Dockerfile, etc.

# Check if the user has Docker permissions
if ! docker info >/dev/null 2>&1; then
  echo "This script requires Docker permissions. You can either:"
  echo "1) Run it with 'sudo ./start.sh'"
  echo "2) Add your user to the 'docker' group with 'sudo usermod -aG docker $USER' and log out/in"
  echo "Using 'sudo' for Docker commands in this run..."
else
  echo "Docker permissions detected. Running without sudo for Docker commands."
fi

# Function to clean up existing containers and volumes
cleanup() {
  echo "Cleaning up existing containers and volumes..."
  # Stop and remove the container if it exists
  if sudo docker ps -a -q -f name=inventory_app | grep -q .; then
    sudo docker stop inventory_app
    sudo docker rm inventory_app
  fi
  # Remove the Docker volume if it exists (for option 2)
  if sudo docker volume ls -q -f name=inventory_db | grep -q .; then
    sudo docker volume rm inventory_db
  fi
}

# Function to set permissions on the host directory
set_host_permissions() {
  echo "Setting permissions on host directory ($(pwd))..."
  sudo chown -R 1000:1000 "$(pwd)"
  sudo chmod -R 755 "$(pwd)"
}

# Function to build the Docker image
build_image() {
  echo "Building Docker image 'inventory_app:v1'..."
  sudo docker build -t inventory_app:v1 .
  if [ $? -ne 0 ]; then
    echo "Error: Failed to build Docker image."
    exit 1
  fi
}

# Function to run container with local directory volume
run_local_volume() {
  echo "Running container with database saved in local directory ($(pwd))..."
  sudo docker run -d -p 5049:5049 -v "$(pwd):/app" --name inventory_app inventory_app:v1
  if [ $? -eq 0 ]; then
    echo "Container 'inventory_app' is running. Access it at http://localhost:5049"
    echo "Logs can be viewed with: sudo docker logs inventory_app"
  else
    echo "Error: Failed to start container."
    exit 1
  fi
}

# Function to run container with Docker volume
run_docker_volume() {
  echo "Creating Docker volume 'inventory_db' if it doesn't exist..."
  sudo docker volume create inventory_db
  echo "Running container with database saved in Docker volume 'inventory_db'..."
  sudo docker run -d -p 5049:5049 -v inventory_db:/app --name inventory_app inventory_app:v1
  if [ $? -eq 0 ]; then
    echo "Container 'inventory_app' is running. Access it at http://localhost:5049"
    echo "Logs can be viewed with: sudo docker logs inventory_app"
  else
    echo "Error: Failed to start container."
    exit 1
  fi
}

# Function to run Gunicorn without container
run_gunicorn() {
  echo "Running app with Gunicorn (no container)..."
  # Check if requirements are installed
  if [ ! -f "requirements.txt" ]; then
    echo "Error: requirements.txt not found."
    exit 1
  fi
  pip install -r requirements.txt
  # Ensure the database is initialized
  python3 -c "from app import init_db; init_db()"
  nohup gunicorn --workers 4 --bind 0.0.0.0:5049 app:app > gunicorn.log 2>&1 &
  if [ $? -eq 0 ]; then
    echo "Gunicorn started in the background. Logs are in gunicorn.log"
    echo "Access it at http://localhost:5049"
  else
    echo "Error: Failed to start Gunicorn."
    exit 1
  fi

  # Ask about auto-start on reboot
  read -p "Would you like Gunicorn to start automatically on system restart? (y/n): " autostart
  if [ "$autostart" = "y" ] || [ "$autostart" = "Y" ]; then
    setup_autostart
  fi
}

# Function to set up Gunicorn as a systemd service for auto-start
setup_autostart() {
  echo "Setting up Gunicorn to start on system restart..."
  SERVICE_FILE="/etc/systemd/system/inventory_app.service"
  CURRENT_DIR=$(pwd)

  # Create systemd service file
  cat <<EOF | sudo tee $SERVICE_FILE > /dev/null
[Unit]
Description=Inventory App Gunicorn Service
After=network.target

[Service]
User=$USER
WorkingDirectory=$CURRENT_DIR
ExecStart=/usr/local/bin/gunicorn --workers 4 --bind 0.0.0.0:5049 app:app
Restart=always
StandardOutput=file:$CURRENT_DIR/gunicorn.log
StandardError=file:$CURRENT_DIR/gunicorn.log

[Install]
WantedBy=multi-user.target
EOF

  # Reload systemd, enable, and start the service
  sudo systemctl daemon-reload
  sudo systemctl enable inventory_app.service
  sudo systemctl start inventory_app.service

  if [ $? -eq 0 ]; then
    echo "Gunicorn service set up successfully. It will start on reboot."
    echo "Check status with: sudo systemctl status inventory_app.service"
  else
    echo "Error: Failed to set up Gunicorn service."
    exit 1
  fi
}

# Main menu
echo "Inventory App Automation Script"
echo "-----------------------------"
echo "Choose an option:"
echo "1) Run Docker container with database in local directory"
echo "2) Run Docker container with database in Docker volume"
echo "3) Run app with Gunicorn (no container)"
read -p "Enter your choice (1-3): " choice

# Process user choice
case $choice in
  1)
    cleanup
    set_host_permissions
    build_image
    run_local_volume
    ;;
  2)
    cleanup
    build_image
    run_docker_volume
    ;;
  3)
    # Stop any running Gunicorn processes
    pkill gunicorn 2>/dev/null || true
    # Remove the local database file if it exists
    rm -f inventory.db
    run_gunicorn
    ;;
  *)
    echo "Invalid choice. Please run the script again and select 1, 2, or 3."
    exit 1
    ;;
esac

exit 0