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
 ____                 __     ______  _   _    __          ____    __  __ _____ 
|  _ \ ___  ___ _ __ \ \   / /  _ \| \ | |   \ \        / /\ \  |  \/  |_   _|
| |_) / _ \/ _ \ '_ \ \ \ / /| |_) |  \| |    \ \  /\  / /  \ \ | \  / | | |  
|  __/  __/  __/ | | | \ V / |  __/| |\  |     \ \/  \/ /   / / | |\/| | | |  
|_|   \___|\___|_| |_|  \_/  |_|   |_| \_|      \__/\__/   /_/  |_|  |_| |_|  
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
 ____                 __     ______  _   _    __          ____    __  __ _____ 
|  _ \ ___  ___ _ __ \ \   / /  _ \| \ | |   \ \        / /\ \  |  \/  |_   _|
| |_) / _ \/ _ \ '_ \ \ \ / /| |_) |  \| |    \ \  /\  / /  \ \ | \  / | | |  
|  __/  __/  __/ | | | \ V / |  __/| |\  |     \ \/  \/ /   / / | |\/| | | |  
|_|   \___|\___|_| |_|  \_/  |_|   |_| \_|      \__/\__/   /_/  |_|  |_| |_|  
EOF
echo "=================================================================="
echo
echo "This script will install and configure:"
echo "  - OpenVPN Server"
echo "  - Web Management Interface (port 6969)"
echo
echo "The process will:"
echo "  1. Update your system"
echo "  2. Install required packages"
echo "  3. Configure OpenVPN server"
echo "  4. Set up the web management interface"
echo
read -p "Press Enter to continue or Ctrl+C to cancel..."

# Step 1: Update system
echo_message "Updating system packages..."
apt update && apt upgrade -y
echo_message "System updated successfully"

# Step 2: Install required packages
echo_message "Installing required packages..."
apt install -y curl wget openvpn easy-rsa apache2 php php-fpm libapache2-mod-php php-json ufw net-tools
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

# Step 6: Set up OpenVPN
echo_message "Setting up OpenVPN..."

# Set up easy-rsa
mkdir -p /etc/openvpn/easy-rsa
cp -r /usr/share/easy-rsa/* /etc/openvpn/easy-rsa/
cd /etc/openvpn/easy-rsa

# Initialize PKI
echo_message "Initializing PKI..."
./easyrsa init-pki

# Build CA (non-interactive)
echo_message "Building CA certificate..."
./easyrsa --batch --req-cn="OpenVPN-CA" build-ca nopass

# Generate server certificate and key
echo_message "Generating server certificate and key..."
./easyrsa --batch build-server-full server nopass

# Generate Diffie-Hellman parameters
echo_message "Generating Diffie-Hellman parameters (this might take a few minutes)..."
./easyrsa gen-dh

# Generate TLS-Auth key
echo_message "Generating TLS-Auth key..."
openvpn --genkey secret /etc/openvpn/ta.key

# Copy certificates and keys
cp pki/ca.crt pki/dh.pem pki/issued/server.crt pki/private/server.key /etc/openvpn/

# Create OpenVPN server configuration
echo_message "Creating OpenVPN server configuration..."
cat > /etc/openvpn/server.conf << EOF
port $PORT
proto $PROTOCOL
dev tun
ca ca.crt
cert server.crt
key server.key
dh dh.pem
topology subnet
server 10.8.0.0 255.255.255.0
ifconfig-pool-persist ipp.txt
push "redirect-gateway def1 bypass-dhcp"
push "dhcp-option DNS 8.8.8.8"
push "dhcp-option DNS 8.8.4.4"
keepalive 10 120
tls-auth ta.key 0
cipher AES-256-GCM
auth SHA256
user nobody
group nogroup
persist-key
persist-tun
status openvpn-status.log
verb 3
EOF

# Enable IP forwarding
echo_message "Enabling IP forwarding..."
echo 'net.ipv4.ip_forward = 1' > /etc/sysctl.d/99-openvpn.conf
sysctl --system

# Configure firewall
echo_message "Configuring firewall..."
systemctl enable ufw
systemctl start ufw
ufw allow ssh
ufw allow $PORT/$PROTOCOL
ufw allow 80/tcp
ufw allow 6969/tcp
echo "y" | ufw enable

# Get default network interface
NIC=$(ip -4 route ls | grep default | grep -Po '(?<=dev )(\S+)' | head -1)

# Configure NAT for OpenVPN
iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE
echo "iptables -t nat -A POSTROUTING -s 10.8.0.0/24 -o $NIC -j MASQUERADE" > /etc/rc.local
chmod +x /etc/rc.local

# Enable and start OpenVPN service
systemctl enable openvpn@server
systemctl start openvpn@server

echo_message "OpenVPN server has been set up and started"

# Step 7: Set up web management interface on port 6969
echo_message "Setting up web management interface..."

# Create directory for web interface
mkdir -p /var/www/vpn-admin
mkdir -p /var/www/vpn-admin/clients

# Create web admin password
ADMIN_USER="admin"
ADMIN_PASS=$(openssl rand -base64 12)
ADMIN_PASS_HASH=$(echo -n "$ADMIN_PASS" | md5sum | awk '{print $1}')

# Create .htpasswd file
echo "$ADMIN_USER:$ADMIN_PASS_HASH" > /var/www/vpn-admin/.htpasswd

# Create Apache virtual host for web interface
cat > /etc/apache2/sites-available/vpn-admin.conf << EOF
Listen 6969
<VirtualHost *:6969>
    ServerAdmin webmaster@localhost
    DocumentRoot /var/www/vpn-admin

    <Directory /var/www/vpn-admin>
        Options -Indexes +FollowSymLinks
        AllowOverride All
        Require all granted
    </Directory>

    ErrorLog \${APACHE_LOG_DIR}/vpn-admin-error.log
    CustomLog \${APACHE_LOG_DIR}/vpn-admin-access.log combined
</VirtualHost>
EOF

# Create .htaccess for authentication
cat > /var/www/vpn-admin/.htaccess << EOF
AuthType Basic
AuthName "VPN Admin Area"
AuthUserFile /var/www/vpn-admin/.htpasswd
Require valid-user
EOF

# Generate index page and functionality
cat > /var/www/vpn-admin/index.php << EOF
<?php
// Prevent direct access to this file
if (!defined('ADMIN_PANEL')) {
    define('ADMIN_PANEL', true);
}

// Include functions file
require_once('functions.php');
?>
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>OpenVPN Management Interface</title>
    <link rel="stylesheet" href="style.css">
    <script src="https://unpkg.com/alpinejs@3.x.x/dist/cdn.min.js" defer></script>
</head>
<body x-data="{ activeTab: 'users' }">
    <div class="container">
        <header>
            <h1>OpenVPN Management Interface</h1>
            <div class="server-info">
                <p><strong>Server IP:</strong> <?php echo get_server_ip(); ?></p>
                <p><strong>Protocol:</strong> <?php echo get_server_protocol(); ?></p>
                <p><strong>Port:</strong> <?php echo get_server_port(); ?></p>
                <p><strong>Status:</strong> <span class="status-<?php echo is_openvpn_running() ? 'online' : 'offline'; ?>">
                    <?php echo is_openvpn_running() ? 'Online' : 'Offline'; ?>
                </span></p>
            </div>
        </header>
        
        <nav>
            <ul class="tabs">
                <li><a href="#" @click.prevent="activeTab = 'users'" :class="{ 'active': activeTab === 'users' }">Users</a></li>
                <li><a href="#" @click.prevent="activeTab = 'service'" :class="{ 'active': activeTab === 'service' }">Service</a></li>
                <li><a href="#" @click.prevent="activeTab = 'logs'" :class="{ 'active': activeTab === 'logs' }">Logs</a></li>
            </ul>
        </nav>
        
        <main>
            <div x-show="activeTab === 'users'" class="tab-content">
                <div class="card">
                    <h2>VPN Users</h2>
                    <div class="action-bar">
                        <form method="post" action="actions.php">
                            <input type="hidden" name="action" value="add_user">
                            <input type="text" name="username" placeholder="New username" required>
                            <button type="submit" class="btn primary">Add User</button>
                        </form>
                    </div>
                    
                    <div class="users-list">
                        <table>
                            <thead>
                                <tr>
                                    <th>Username</th>
                                    <th>Created</th>
                                    <th>Actions</th>
                                </tr>
                            </thead>
                            <tbody>
                                <?php foreach(get_user_list() as $user): ?>
                                <tr>
                                    <td><?php echo $user['name']; ?></td>
                                    <td><?php echo $user['created']; ?></td>
                                    <td class="actions">
                                        <a href="actions.php?action=download&user=<?php echo $user['name']; ?>" class="btn secondary">Download</a>
                                        <form method="post" action="actions.php" onsubmit="return confirm('Are you sure you want to delete this user?');">
                                            <input type="hidden" name="action" value="delete_user">
                                            <input type="hidden" name="username" value="<?php echo $user['name']; ?>">
                                            <button type="submit" class="btn danger">Delete</button>
                                        </form>
                                    </td>
                                </tr>
                                <?php endforeach; ?>
                            </tbody>
                        </table>
                    </div>
                </div>
            </div>
            
            <div x-show="activeTab === 'service'" class="tab-content">
                <div class="card">
                    <h2>Service Control</h2>
                    <div class="service-controls">
                        <div class="service-status">
                            <p><strong>Current Status:</strong> 
                                <span class="status-<?php echo is_openvpn_running() ? 'online' : 'offline'; ?>">
                                    <?php echo is_openvpn_running() ? 'Running' : 'Stopped'; ?>
                                </span>
                            </p>
                        </div>
                        <div class="service-buttons">
                            <form method="post" action="actions.php">
                                <input type="hidden" name="action" value="start_service">
                                <button type="submit" class="btn success" <?php if(is_openvpn_running()) echo 'disabled'; ?>>Start Service</button>
                            </form>
                            <form method="post" action="actions.php">
                                <input type="hidden" name="action" value="stop_service">
                                <button type="submit" class="btn danger" <?php if(!is_openvpn_running()) echo 'disabled'; ?>>Stop Service</button>
                            </form>
                            <form method="post" action="actions.php">
                                <input type="hidden" name="action" value="restart_service">
                                <button type="submit" class="btn primary">Restart Service</button>
                            </form>
                        </div>
                    </div>
                </div>
            </div>
            
            <div x-show="activeTab === 'logs'" class="tab-content">
                <div class="card">
                    <h2>Server Logs</h2>
                    <div class="logs-container">
                        <pre><?php echo get_vpn_logs(); ?></pre>
                    </div>
                </div>
            </div>
        </main>
        
        <footer>
            <p>OpenVPN Management Interface &copy; <?php echo date('Y'); ?></p>
        </footer>
    </div>
</body>
</html>
EOF

# Create actions handler
cat > /var/www/vpn-admin/actions.php << EOF
<?php
// Prevent direct access
if (!defined('ADMIN_PANEL')) {
    define('ADMIN_PANEL', true);
}

// Include functions
require_once('functions.php');

// Handle actions
if (isset(\$_POST['action']) || isset(\$_GET['action'])) {
    \$action = isset(\$_POST['action']) ? \$_POST['action'] : \$_GET['action'];
    
    switch (\$action) {
        case 'add_user':
            if (isset(\$_POST['username'])) {
                \$username = sanitize_username(\$_POST['username']);
                if (create_client(\$username)) {
                    set_message("success", "User \$username created successfully");
                } else {
                    set_message("error", "Failed to create user \$username");
                }
            }
            break;
            
        case 'delete_user':
            if (isset(\$_POST['username'])) {
                \$username = sanitize_username(\$_POST['username']);
                if (revoke_client(\$username)) {
                    set_message("success", "User \$username revoked successfully");
                } else {
                    set_message("error", "Failed to revoke user \$username");
                }
            }
            break;
            
        case 'download':
            if (isset(\$_GET['user'])) {
                \$username = sanitize_username(\$_GET['user']);
                download_client_config(\$username);
                exit; // Stop execution after download
            }
            break;
            
        case 'start_service':
            if (start_openvpn_service()) {
                set_message("success", "OpenVPN service started successfully");
            } else {
                set_message("error", "Failed to start OpenVPN service");
            }
            break;
            
        case 'stop_service':
            if (stop_openvpn_service()) {
                set_message("success", "OpenVPN service stopped successfully");
            } else {
                set_message("error", "Failed to stop OpenVPN service");
            }
            break;
            
        case 'restart_service':
            if (restart_openvpn_service()) {
                set_message("success", "OpenVPN service restarted successfully");
            } else {
                set_message("error", "Failed to restart OpenVPN service");
            }
            break;
    }
}

// Redirect back to the main page
header("Location: index.php");
exit;
EOF

# Create functions file
cat > /var/www/vpn-admin/functions.php << EOF
<?php
// Prevent direct access
if (!defined('ADMIN_PANEL')) {
    die('Direct access not permitted');
}

// Start session for flash messages
session_start();

/**
 * Get server IP
 */
function get_server_ip() {
    return trim(file_get_contents('/var/www/vpn-admin/server_ip.txt'));
}

/**
 * Get server protocol
 */
function get_server_protocol() {
    return trim(file_get_contents('/var/www/vpn-admin/server_protocol.txt'));
}

/**
 * Get server port
 */
function get_server_port() {
    return trim(file_get_contents('/var/www/vpn-admin/server_port.txt'));
}

/**
 * Check if OpenVPN is running
 */
function is_openvpn_running() {
    \$output = [];
    exec('systemctl is-active openvpn@server', \$output);
    return (isset(\$output[0]) && \$output[0] === 'active');
}

/**
 * Get list of VPN users
 */
function get_user_list() {
    \$users = [];
    \$output = [];
    exec('cd /etc/openvpn/easy-rsa && ./easyrsa list-issued', \$output);
    
    foreach (\$output as \$line) {
        if (strpos(\$line, 'server') === false && preg_match('/(.+?)[\s]+[\d-]+[\s]+(.+)/', \$line, \$matches)) {
            if (isset(\$matches[1]) && trim(\$matches[1]) != '') {
                \$users[] = [
                    'name' => trim(\$matches[1]),
                    'created' => isset(\$matches[2]) ? trim(\$matches[2]) : 'Unknown'
                ];
            }
        }
    }
    
    return \$users;
}

/**
 * Create a new client
 */
function create_client(\$username) {
    \$username = sanitize_username(\$username);
    
    // Check if user already exists
    \$users = get_user_list();
    foreach (\$users as \$user) {
        if (\$user['name'] === \$username) {
            return false; // User already exists
        }
    }
    
    // Generate client certificates
    \$output = [];
    \$result = 0;
    exec('cd /etc/openvpn/easy-rsa && ./easyrsa build-client-full "' . \$username . '" nopass', \$output, \$result);
    
    if (\$result !== 0) {
        return false;
    }
    
    // Generate client config
    generate_client_config(\$username);
    
    return true;
}

/**
 * Generate client config file
 */
function generate_client_config(\$username) {
    \$server_ip = get_server_ip();
    \$server_protocol = get_server_protocol();
    \$server_port = get_server_port();
    
    // Read key/cert files
    \$ca = file_get_contents('/etc/openvpn/ca.crt');
    \$ta = file_get_contents('/etc/openvpn/ta.key');
    \$cert = file_get_contents("/etc/openvpn/easy-rsa/pki/issued/{\$username}.crt");
    
    // Extract the client certificate section only
    preg_match('/-----BEGIN CERTIFICATE-----(.+?)-----END CERTIFICATE-----/s', \$cert, \$cert_matches);
    \$client_cert = "-----BEGIN CERTIFICATE-----" . \$cert_matches[1] . "-----END CERTIFICATE-----";
    
    \$key = file_get_contents("/etc/openvpn/easy-rsa/pki/private/{\$username}.key");
    
    \$config = "
client
dev tun
proto {\$server_protocol}
remote {\$server_ip} {\$server_port}
resolv-retry infinite
nobind
persist-key
persist-tun
remote-cert-tls server
cipher AES-256-GCM
auth SHA256
verb 3
key-direction 1

<ca>
{\$ca}
</ca>

<cert>
{\$client_cert}
</cert>

<key>
{\$key}
</key>

<tls-auth>
{\$ta}
</tls-auth>
";

    file_put_contents("/var/www/vpn-admin/clients/{\$username}.ovpn", \$config);
    
    return true;
}

/**
 * Revoke a client certificate
 */
function revoke_client(\$username) {
    \$username = sanitize_username(\$username);
    
    // Revoke certificate
    \$output = [];
    \$result = 0;
    exec('cd /etc/openvpn/easy-rsa && ./easyrsa revoke "' . \$username . '" && ./easyrsa gen-crl', \$output, \$result);
    
    // Remove client config
    if (file_exists("/var/www/vpn-admin/clients/{\$username}.ovpn")) {
        unlink("/var/www/vpn-admin/clients/{\$username}.ovpn");
    }
    
    return true;
}

/**
 * Download client config
 */
function download_client_config(\$username) {
    \$username = sanitize_username(\$username);
    \$file_path = "/var/www/vpn-admin/clients/{\$username}.ovpn";
    
    if (!file_exists(\$file_path)) {
        // If file doesn't exist, try to generate it
        if (!generate_client_config(\$username)) {
            die("Could not generate config file for {\$username}");
        }
    }
    
    // Set headers for download
    header('Content-Type: application/octet-stream');
    header('Content-Disposition: attachment; filename="' . \$username . '.ovpn"');
    header('Content-Length: ' . filesize(\$file_path));
    
    // Send file
    readfile(\$file_path);
    exit;
}

/**
 * Start OpenVPN service
 */
function start_openvpn_service() {
    \$output = [];
    \$result = 0;
    exec('systemctl start openvpn@server', \$output, \$result);
    return (\$result === 0);
}

/**
 * Stop OpenVPN service
 */
function stop_openvpn_service() {
    \$output = [];
    \$result = 0;
    exec('systemctl stop openvpn@server', \$output, \$result);
    return (\$result === 0);
}

/**
 * Restart OpenVPN service
 */
function restart_openvpn_service() {
    \$output = [];
    \$result = 0;
    exec('systemctl restart openvpn@server', \$output, \$result);
    return (\$result === 0);
}

/**
 * Get OpenVPN logs
 */
function get_vpn_logs() {
    \$logs = '';
    
    if (file_exists('/etc/openvpn/openvpn-status.log')) {
        \$logs = file_get_contents('/etc/openvpn/openvpn-status.log');
        
        // Limit logs to last 100 lines
        \$lines = explode("\n", \$logs);
        if (count(\$lines) > 100) {
            \$lines = array_slice(\$lines, -100);
            \$logs = implode("\n", \$lines);
        }
    } else {
        \$logs = "Log file not found";
    }
    
    return \$logs;
}

/**
 * Set a flash message
 */
function set_message(\$type, \$message) {
    \$_SESSION['flash_message'] = [
        'type' => \$type,
        'message' => \$message
    ];
}

/**
 * Get and clear flash message
 */
function get_message() {
    if (isset(\$_SESSION['flash_message'])) {
        \$message = \$_SESSION['flash_message'];
        unset(\$_SESSION['flash_message']);
        return \$message;
    }
    return null;
}

/**
 * Sanitize username
 */
function sanitize_username(\$username) {
    // Remove any special characters, allow only letters, numbers, and underscores
    return preg_replace('/[^a-zA-Z0-9_]/', '', \$username);
}
EOF

# Create stylesheet
cat > /var/www/vpn-admin/style.css << EOF
:root {
    --primary: #3B82F6;
    --primary-dark: #2563EB;
    --success: #10B981;
    --success-dark: #059669;
    --danger: #EF4444;
    --danger-dark: #DC2626;
    --secondary: #6B7280;
    --secondary-dark: #4B5563;
    --background: #F3F4F6;
    --card: #FFFFFF;
    --text: #1F2937;
    --text-light: #6B7280;
    --border: #E5E7EB;
    --spacing: 1rem;
}

* {
    box-sizing: border-box;
    margin: 0;
    padding: 0;
}

body {
    font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, 'Helvetica Neue', Arial, sans-serif;
    background-color: var(--background);
    color: var(--text);
    line-height: 1.5;
}

.container {
    max-width: 1200px;
    margin: 0 auto;
    padding: var(--spacing);
}

header {
    margin-bottom: calc(var(--spacing) * 2);
    padding-bottom: var(--spacing);
    border-bottom: 1px solid var(--border);
    display: flex;
    flex-direction: column;
    gap: var(--spacing);
}

@media (min-width: 768px) {
    header {
        flex-direction: row;
        justify-content: space-between;
        align-items: center;
    }
}

h1 {
    font-size: 1.8rem;
    font-weight: 600;
    color: var(--text);
}

h2 {
    font-size: 1.4rem;
    font-weight: 600;
    margin-bottom: var(--spacing);
}

.server-info {
    display: flex;
    flex-wrap: wrap;
    gap: calc(var(--spacing) * 0.75);
}

.server-info p {
    margin-right: calc(var(--spacing) * 1.5);
}

.status-online {
    color: var(--success);
    font-weight: 600;
}

.status-offline {
    color: var(--danger);
    font-weight: 600;
}

nav {
    margin-bottom: calc(var(--spacing) * 2);
}

.tabs {
    display: flex;
    list-style: none;
    gap: 0;
    border-bottom: 1px solid var(--border);
}

.tabs li a {
    display: inline-block;
    padding: calc(var(--spacing) * 0.75) var(--spacing);
    color: var(--text-light);
    text-decoration: none;
    border-bottom: 2px solid transparent;
    margin-bottom: -1px;
    transition: all 0.2s ease;
}

.tabs li a:hover {
    color: var(--primary);
}

.tabs li a.active {
    color: var(--primary);
    border-bottom-color: var(--primary);
}

.card {
    background-color: var(--card);
    border-radius: 8px;
    box-shadow: 0 1px 3px rgba(0, 0, 0, 0.1);
    padding: calc(var(--spacing) * 1.5);
    margin-bottom: var(--spacing);
}

.action-bar {
    display: flex;
    margin-bottom: var(--spacing);
}

.action-bar form {
    
    display: flex;
    gap: var(--spacing);
}

.action-bar input[type="text"] {
    flex: 1;
    min-width: 200px;
}

input[type="text"] {
    padding: 0.5rem 0.75rem;
    border: 1px solid var(--border);
    border-radius: 4px;
    font-size: 1rem;
}

.btn {
    display: inline-block;
    padding: 0.5rem 1rem;
    border: none;
    border-radius: 4px;
    font-size: 0.9rem;
    font-weight: 500;
    text-align: center;
    cursor: pointer;
    transition: background-color 0.2s ease, transform 0.1s ease;
}

.btn:hover {
    transform: translateY(-1px);
}

.btn:active {
    transform: translateY(0);
}

.btn.primary {
    background-color: var(--primary);
    color: white;
}

.btn.primary:hover {
    background-color: var(--primary-dark);
}

.btn.secondary {
    background-color: var(--secondary);
    color: white;
}

.btn.secondary:hover {
    background-color: var(--secondary-dark);
}

.btn.success {
    background-color: var(--success);
    color: white;
}

.btn.success:hover {
    background-color: var(--success-dark);
}

.btn.danger {
    background-color: var(--danger);
    color: white;
}

.btn.danger:hover {
    background-color: var(--danger-dark);
}

.btn:disabled {
    opacity: 0.5;
    cursor: not-allowed;
}

.btn:disabled:hover {
    transform: none;
}

table {
    width: 100%;
    border-collapse: collapse;
}

table th, table td {
    padding: 0.75rem;
    text-align: left;
    border-bottom: 1px solid var(--border);
}

table th {
    font-weight: 600;
    color: var(--text);
}

.actions {
    display: flex;
    gap: 0.5rem;
}

.service-controls {
    display: flex;
    flex-direction: column;
    gap: var(--spacing);
}

.service-buttons {
    display: flex;
    gap: var(--spacing);
}

.logs-container {
    background-color: #1E293B;
    color: #E2E8F0;
    padding: var(--spacing);
    border-radius: 4px;
    overflow-x: auto;
    max-height: 400px;
    overflow-y: auto;
}

pre {
    font-family: monospace;
    white-space: pre-wrap;
    word-break: break-all;
}

footer {
    margin-top: calc(var(--spacing) * 3);
    padding-top: var(--spacing);
    border-top: 1px solid var(--border);
    text-align: center;
    color: var(--text-light);
    font-size: 0.9rem;
}

@media (max-width: 768px) {
    .action-bar form {
        flex-direction: column;
    }
    
    .service-buttons {
        flex-direction: column;
    }
    
    table, thead, tbody, th, td, tr {
        display: block;
    }
    
    table thead tr {
        position: absolute;
        top: -9999px;
        left: -9999px;
    }
    
    table tr {
        border-bottom: 1px solid var(--border);
        margin-bottom: 1rem;
    }
    
    table td {
        border: none;
        border-bottom: 1px solid var(--border);
        position: relative;
        padding-left: 50%;
    }
    
    table td:before {
        position: absolute;
        top: 0.75rem;
        left: 0.75rem;
        width: 45%;
        padding-right: 10px;
        white-space: nowrap;
        font-weight: 600;
    }
    
    table td:nth-of-type(1):before { content: "Username"; }
    table td:nth-of-type(2):before { content: "Created"; }
    table td:nth-of-type(3):before { content: "Actions"; }
}
EOF

# Store server information for web interface
echo "$PUBLIC_IP" > /var/www/vpn-admin/server_ip.txt
echo "$PROTOCOL" > /var/www/vpn-admin/server_protocol.txt
echo "$PORT" > /var/www/vpn-admin/server_port.txt

# Set correct permissions
chown -R www-data:www-data /var/www/vpn-admin
chmod -R 750 /var/www/vpn-admin
chmod 640 /var/www/vpn-admin/.htpasswd

# Enable the virtual host
a2ensite vpn-admin.conf

# Enable required modules
a2enmod rewrite
a2enmod ssl
a2enmod headers

# Restart Apache
systemctl restart apache2

# Create README.md
cat > README.md << EOF
# OpenVPN Server with Web Management Interface

This project installs an OpenVPN server with a web-based management interface on Debian 12.

## Prerequisites

- Debian 12 (Bookworm) fresh installation
- Root access
- Internet connectivity

## Installation

1. Download the script:
   \`\`\`
   wget https://your-domain.com/download/install.sh
   \`\`\`

2. Make it executable:
   \`\`\`
   chmod +x install.sh
   \`\`\`

3. Run the script:
   \`\`\`
   sudo ./install.sh
   \`\`\`

4. Follow the interactive prompts to configure your OpenVPN server.

## Web Interface

The web interface is accessible at:
\`\`\`
http://YOUR_SERVER_IP:6969/
\`\`\`

Default credentials:
- Username: admin
- Password: $ADMIN_PASS

## Features

- Add/remove VPN users
- Download client .ovpn configuration files
- Control OpenVPN service (start/stop/restart)
- View server logs

## Security

- Basic authentication protects the web interface
- Firewall rules automatically configured
- TLS encryption for VPN connections

## License

This project is open source and available under the MIT License.
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
echo "Please save these credentials in a secure location."
echo "You can also find them in the README.md file in the current directory."
echo
echo "=================================================================="