#!/bin/bash

###############################################################################
# WireGuard Client Generator
# Easily add new clients to your WireGuard VPN server
###############################################################################

set -e

# Colors
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

print_info() { echo -e "${GREEN}[INFO]${NC} $1"; }
print_error() { echo -e "${RED}[ERROR]${NC} $1"; }
print_warning() { echo -e "${YELLOW}[WARNING]${NC} $1"; }
print_success() { echo -e "${GREEN}[SUCCESS]${NC} $1"; }

# Check root
if [[ $EUID -ne 0 ]]; then
    print_error "This script must be run as root"
    exit 1
fi

clear
echo "=========================================="
echo "   WireGuard Client Generator"
echo "=========================================="
echo ""

# Configuration
WG_DIR="/etc/wireguard"
WG_PORT="51820"
CLIENT_DIR="$WG_DIR/clients"

# Check if WireGuard is installed
if ! command -v wg &> /dev/null; then
    print_error "WireGuard is not installed"
    exit 1
fi

# Check if server is configured
if [[ ! -f "$WG_DIR/wg0.conf" ]]; then
    print_error "WireGuard server is not configured"
    exit 1
fi

# Get server public key
if [[ ! -f "$WG_DIR/server_public.key" ]]; then
    print_error "Server public key not found"
    exit 1
fi
SERVER_PUBLIC_KEY=$(cat $WG_DIR/server_public.key)

# Get server public IP
print_info "Detecting server public IP..."
SERVER_PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || \
                   curl -s --max-time 5 icanhazip.com 2>/dev/null || \
                   curl -s --max-time 5 ipinfo.io/ip 2>/dev/null)

if [[ -z $SERVER_PUBLIC_IP ]]; then
    print_warning "Could not detect public IP automatically"
    read -p "Enter your server public IP: " SERVER_PUBLIC_IP
fi

print_info "Server IP: $SERVER_PUBLIC_IP"

# Get existing clients to find next available IP
print_info "Checking existing clients..."
EXISTING_IPS=$(grep -oP "AllowedIPs = 10\.0\.0\.\K\d+" $WG_DIR/wg0.conf 2>/dev/null | sort -n | tail -1)

if [[ -z $EXISTING_IPS ]]; then
    NEXT_IP=2
else
    NEXT_IP=$((EXISTING_IPS + 1))
fi

if [[ $NEXT_IP -gt 254 ]]; then
    print_error "No more IP addresses available in 10.0.0.0/24 range"
    exit 1
fi

CLIENT_IP="10.0.0.$NEXT_IP/32"

# Get client name from environment variable, argument, or prompt
if [[ ! -z $CLIENT_NAME ]]; then
    # CLIENT_NAME set via environment variable (for curl | bash usage)
    print_info "Using client name: $CLIENT_NAME"
elif [[ ! -z $1 ]]; then
    # CLIENT_NAME passed as argument
    CLIENT_NAME="$1"
    print_info "Using client name: $CLIENT_NAME"
else
    # Interactive mode - prompt for input
    echo ""
    read -p "Enter client name (e.g., phone, laptop, john-phone): " CLIENT_NAME
    
    if [[ -z $CLIENT_NAME ]]; then
        print_error "Client name cannot be empty"
        echo ""
        print_info "Usage options:"
        echo "  1. Interactive: sudo ./add.sh"
        echo "  2. With argument: sudo ./add.sh client-name"
        echo "  3. Via curl: curl -fsSL URL | sudo CLIENT_NAME=client-name bash"
        exit 1
    fi
fi

# Sanitize client name
CLIENT_NAME=$(echo "$CLIENT_NAME" | tr ' ' '-' | tr '[:upper:]' '[:lower:]')

# Check if client already exists
if [[ -f "$CLIENT_DIR/${CLIENT_NAME}.conf" ]]; then
    print_error "Client '$CLIENT_NAME' already exists"
    exit 1
fi

# Auto-assign IP (no prompt)
print_info "Auto-assigned IP: $CLIENT_IP"

print_info "Generating keys for client '$CLIENT_NAME'..."

# Create client directory
mkdir -p $CLIENT_DIR

# Generate client keys
CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)

# Create client configuration file
print_info "Creating client configuration..."
cat > $CLIENT_DIR/${CLIENT_NAME}.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $CLIENT_IP
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_PUBLIC_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

chmod 600 $CLIENT_DIR/${CLIENT_NAME}.conf

# Add client to server configuration
print_info "Adding client to server configuration..."
cat >> $WG_DIR/wg0.conf <<EOF

# Client: $CLIENT_NAME (Added: $(date '+%Y-%m-%d %H:%M:%S'))
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP
EOF

# Restart WireGuard
print_info "Restarting WireGuard service..."
systemctl restart wg-quick@wg0

if systemctl is-active --quiet wg-quick@wg0; then
    print_success "WireGuard service restarted successfully"
else
    print_error "Failed to restart WireGuard service"
    exit 1
fi

# Display results
echo ""
echo "=========================================="
print_success "Client Created Successfully!"
echo "=========================================="
echo ""

print_info "📋 Client Details:"
echo "  ├─ Name: $CLIENT_NAME"
echo "  ├─ IP Address: $CLIENT_IP"
echo "  ├─ Public Key: $CLIENT_PUBLIC_KEY"
echo "  └─ Config File: $CLIENT_DIR/${CLIENT_NAME}.conf"
echo ""

# Generate QR code
if command -v qrencode &> /dev/null; then
    print_info "📱 QR Code for Mobile Devices:"
    echo ""
    qrencode -t ansiutf8 < $CLIENT_DIR/${CLIENT_NAME}.conf
    echo ""
    
    # Save QR code as PNG if possible
    QR_FILE="$CLIENT_DIR/${CLIENT_NAME}-qr.png"
    qrencode -o "$QR_FILE" < $CLIENT_DIR/${CLIENT_NAME}.conf 2>/dev/null && \
        print_info "QR code image saved: $QR_FILE"
else
    print_warning "Install 'qrencode' to generate QR codes:"
    echo "  apt install qrencode"
    echo ""
fi

echo "=========================================="
print_info "Client Configuration File:"
echo "=========================================="
cat $CLIENT_DIR/${CLIENT_NAME}.conf
echo "=========================================="
echo ""

print_info "📱 How to Use This Configuration:"
echo ""
echo "OPTION 1 - QR Code (Easiest for Mobile):"
echo "  1. Open WireGuard app on your phone"
echo "  2. Tap '+' button"
echo "  3. Select 'Scan from QR code'"
echo "  4. Scan the QR code shown above"
echo ""
echo "OPTION 2 - Import Config File:"
echo "  1. Download the config file from:"
echo "     $CLIENT_DIR/${CLIENT_NAME}.conf"
echo "  2. Import it into WireGuard app/client"
echo ""
echo "OPTION 3 - Download via SCP (from your computer):"
echo "  scp root@$SERVER_PUBLIC_IP:$CLIENT_DIR/${CLIENT_NAME}.conf ."
echo ""

print_info "🔌 Active Connections:"
wg show wg0 2>/dev/null || echo "No active connections yet"
echo ""

print_info "📊 Total Clients Configured:"
TOTAL_CLIENTS=$(ls -1 $CLIENT_DIR/*.conf 2>/dev/null | wc -l)
echo "  $TOTAL_CLIENTS client(s) configured"
echo ""

print_success "✅ Client '$CLIENT_NAME' is ready to connect!"
echo ""
