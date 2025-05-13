#!/bin/bash

# OpenVPN Server Installer with Web Management Interface
# For Debian 12 systems

# Text formatting
BOLD='\033[1m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
RED='\033[0;31m'
NC='\033[0m' # No Color

# ASCII Art Banner
cat << "EOF"
 ____                __     ______  _   _   
|  _ \ ___  ___ _ __ \ \   / /  _ \| \ | |  
| |_) / _ \/ _ \ '_ \ \ \ / /| |_) |  \| |   
|  __/  __/  __/ | | | \ V / |  __/| |\  |   
|_|   \___|\___|_| |_|  \_/  |_|   |_| \_|   
EOF
echo "=================================================================="

# Function to display messages
function echo_message() {
  echo -e "${GREEN}${BOLD}[+] $1${NC}"
}

# Function to display warnings
function echo_warning() {
  echo -e "${YELLOW}${BOLD}[!] $1${NC}"
}

# Function to display errors
function echo_error() {
  echo -e "${RED}${BOLD}[ERROR] $1${NC}"
}

# Check if script is run as root
if [ "$(id -u)" -ne 0 ]; then
  echo_error "This script must be run as root"
  exit 1
fi

# Check if system is Debian 12
if ! grep -q 'Debian GNU/Linux 12' /etc/os-release; then
  echo_warning "This script is designed for Debian 12. Your system may not be compatible."
  read -p "Continue anyway? (y/n): " -n 1 -r
  echo
  if [[ ! $REPLY =~ ^[Yy]$ ]]; then
    exit 1
  fi
fi

# Welcome message
clear
# Show ASCII art banner again after clear
cat << "EOF"
 ____                __     ______  _   _   
|  _ \ ___  ___ _ __ \ \   / /  _ \| \ | |  
| |_) / _ \/ _ \ '_ \ \ \ / /| |_) |  \| |   
|  __/  __/  __/ | | | \ V / |  __/| |\  |   
|_|   \___|\___|_| |_|  \_/  |_|   |_| \_|     
EOF
echo "=================================================================="
echo
echo "This script will install and configure:"
echo "  - OpenVPN Server"
echo "  - Web Management Interface (port 6969)"
echo "  - PostgreSQL Database"
echo
echo "The process will:"
echo "  1. Update your system"
echo "  2. Install required packages"
echo "  3. Configure OpenVPN server"
echo "  4. Set up PostgreSQL database"
echo "  5. Set up the web management interface"
echo
read -p "Press Enter to continue or Ctrl+C to cancel..."

# Step 1: Update system
echo_message "Updating system packages..."
apt update && apt upgrade -y
echo_message "System updated successfully"

# Step 2: Install required packages
echo_message "Installing required packages..."
apt install -y curl wget openvpn easy-rsa apache2 php php-fpm libapache2-mod-php php-json ufw net-tools postgresql postgresql-contrib php-pgsql
echo_message "Required packages installed successfully"

# Step 3: Detect public IP
echo_message "Detecting public IP address..."
PUBLIC_IP=$(curl -s ifconfig.me)
if [ -z "$PUBLIC_IP" ]; then
  echo_warning "Could not detect public IP automatically."
  read -p "Please enter your server's public IP address: " PUBLIC_IP
fi
echo_message "Public IP: $PUBLIC_IP"

# Step 4: Ask for OpenVPN protocol
echo
echo "Please select the protocol for OpenVPN:"
echo "1) UDP (Recommended, faster but might be blocked in some networks)"
echo "2) TCP (More reliable, works through more restrictive firewalls)"
read -p "Enter your choice (1-2): " protocol_choice

case $protocol_choice in
  1)
    PROTOCOL="udp"
    ;;
  2)
    PROTOCOL="tcp"
    ;;
  *)
    echo_warning "Invalid choice. Defaulting to UDP."
    PROTOCOL="udp"
    ;;
esac

echo_message "Protocol selected: ${PROTOCOL}"

# Step 5: Ask for OpenVPN port
echo
read -p "Enter the port for OpenVPN (1194 is the default): " port_choice
if [ -z "$port_choice" ]; then
  PORT="1194"
else
  PORT="$port_choice"
fi

echo_message "Port selected: ${PORT}"

# Step 6: Set up PostgreSQL
echo_message "Setting up PostgreSQL database..."

# Generate random password for database
DB_PASSWORD=$(openssl rand -base64 12)
DB_NAME="openvpn_mgmt"
DB_USER="openvpn_admin"

# Create database and user
sudo -u postgres psql << EOF
CREATE DATABASE $DB_NAME;
CREATE USER $DB_USER WITH ENCRYPTED PASSWORD '$DB_PASSWORD';
GRANT ALL PRIVILEGES ON DATABASE $DB_NAME TO $DB_USER;
\c $DB_NAME
CREATE TABLE IF NOT EXISTS vpn_users (
    id SERIAL PRIMARY KEY,
    username VARCHAR(50) UNIQUE NOT NULL,
    created_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    last_connection TIMESTAMP WITH TIME ZONE,
    bytes_received BIGINT DEFAULT 0,
    bytes_sent BIGINT DEFAULT 0,
    active BOOLEAN DEFAULT true
);
CREATE TABLE IF NOT EXISTS connection_logs (
    id SERIAL PRIMARY KEY,
    user_id INTEGER REFERENCES vpn_users(id),
    connected_at TIMESTAMP WITH TIME ZONE DEFAULT CURRENT_TIMESTAMP,
    disconnected_at TIMESTAMP WITH TIME ZONE,
    bytes_received BIGINT DEFAULT 0,
    bytes_sent BIGINT DEFAULT 0,
    ip_address VARCHAR(45),
    CONSTRAINT fk_user FOREIGN KEY(user_id) REFERENCES vpn_users(id) ON DELETE CASCADE
);
GRANT ALL PRIVILEGES ON ALL TABLES IN SCHEMA public TO $DB_USER;
GRANT USAGE, SELECT ON ALL SEQUENCES IN SCHEMA public TO $DB_USER;
EOF

# Create database configuration file
cat > /var/www/vpn-admin/db_config.php << EOF
<?php
define('DB_HOST', 'localhost');
define('DB_NAME', '$DB_NAME');
define('DB_USER', '$DB_USER');
define('DB_PASS', '$DB_PASSWORD');

try {
    \$pdo = new PDO(
        "pgsql:host=" . DB_HOST . ";dbname=" . DB_NAME,
        DB_USER,
        DB_PASS,
        [PDO::ATTR_ERRMODE => PDO::ERRMODE_EXCEPTION]
    );
} catch (PDOException \$e) {
    die("Connection failed: " . \$e->getMessage());
}
EOF

# Secure the configuration file
chown www-data:www-data /var/www/vpn-admin/db_config.php
chmod 600 /var/www/vpn-admin/db_config.php

[Previous installation script content continues...]

# Add database credentials to README
cat >> README.md << EOF

## Database Information
Database Name: $DB_NAME
Database User: $DB_USER
Database Password: $DB_PASSWORD

IMPORTANT: Store these credentials securely!
EOF

# Display completion information
echo "=================================================================="
echo -e "${GREEN}${BOLD}Installation Complete!${NC}"
echo "=================================================================="
echo
echo "Your OpenVPN server has been successfully set up!"
echo
echo "Web Management Interface: http://$PUBLIC_IP:6969/"
echo "Username: $ADMIN_USER"
echo "Password: $ADMIN_PASS"
echo
echo "Database Credentials:"
echo "Database Name: $DB_NAME"
echo "Database User: $DB_USER"
echo "Database Password: $DB_PASSWORD"
echo
echo "Please save these credentials in a secure location."
echo "You can also find them in the README.md file in the current directory."
echo
echo "=================================================================="