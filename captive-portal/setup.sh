#!/bin/bash
# Setup script for Captive Portal

set -e

echo "========================================="
echo "Captive Portal Setup Script"
echo "========================================="
echo ""

# Check if running from correct directory
if [ ! -f "docker-compose.yml" ]; then
    echo "Error: Please run this script from the captive-portal directory"
    exit 1
fi

# Check if Docker is installed
if ! command -v docker &> /dev/null; then
    echo "Error: Docker is not installed"
    exit 1
fi

# Check if Docker Compose is available (either plugin or standalone)
if docker compose version &> /dev/null; then
    DOCKER_COMPOSE="docker compose"
    echo "✓ Using Docker Compose plugin"
elif command -v docker-compose &> /dev/null; then
    DOCKER_COMPOSE="docker-compose"
    echo "✓ Using standalone docker-compose"
else
    echo "Error: Docker Compose is not installed"
    echo "Install with: sudo apt-get install docker-compose-plugin"
    exit 1
fi

# Create .env if it doesn't exist
if [ ! -f ".env" ]; then
    echo "Creating .env file from template..."
    cp .env.example .env
    
    # Generate secure SECRET_KEY
    SECRET_KEY=$(openssl rand -hex 32)
    # Use @ as delimiter to avoid issues with special characters
    sed -i "s@your_secret_key_here@$SECRET_KEY@" .env
    
    # Generate secure DB_PASSWORD (alphanumeric only to avoid sed issues)
    DB_PASSWORD=$(openssl rand -hex 16)
    sed -i "s@your_secure_password@$DB_PASSWORD@" .env
    
    echo "✓ Created .env file with generated secrets"
    echo ""
    echo "IMPORTANT: Please edit .env and configure:"
    echo "  - SMTP settings (for email)"
    echo "  - ADMIN_EMAIL"
    echo "  - PORTAL_URL (if using domain)"
    echo ""
    read -p "Press Enter when ready to continue..."
else
    echo "✓ .env file already exists"
fi

# Create data directory
mkdir -p data/postgres
echo "✓ Created data directory"

# Pull Docker images
echo ""
echo "Pulling Docker images..."
$DOCKER_COMPOSE pull

# Build application
echo ""
echo "Building application..."
$DOCKER_COMPOSE build

# Start services
echo ""
echo "Starting services..."
$DOCKER_COMPOSE up -d

# Wait for services to be healthy
echo ""
echo "Waiting for services to start..."
sleep 10

# Check service status
echo ""
echo "Service status:"
$DOCKER_COMPOSE ps

# Test health endpoint
echo ""
echo "Testing application health..."
if curl -f http://localhost:8080/health &> /dev/null; then
    echo "✓ Application is healthy"
else
    echo "⚠ Application health check failed - check logs"
fi

# Show admin credentials
echo ""
echo "========================================="
echo "Setup Complete!"
echo "========================================="
echo ""
echo "Access the portal at:"
echo "  User portal:  http://$(hostname -I | awk '{print $1}'):8080"
echo "  Admin panel:  http://$(hostname -I | awk '{print $1}'):8080/admin/login"
echo ""
echo "Default admin credentials:"
echo "  Username: admin"
echo "  Password: admin123"
echo ""
echo "⚠ IMPORTANT: Change the admin password immediately!"
echo ""
echo "Next steps:"
echo "  1. Configure Nginx Proxy Manager to proxy to port 8080"
echo "  2. Add test user in admin panel"
echo "  3. Test registration from a device on VLAN 99"
echo "  4. Configure FreeRADIUS CoA (see README.md)"
echo ""
echo "View logs:"
echo "  $DOCKER_COMPOSE logs -f"
echo ""
echo "Stop services:"
echo "  $DOCKER_COMPOSE down"
echo ""
