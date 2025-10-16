#!/bin/bash

###############################################################################
# WireGuard Auto Installation Script
# Fully automated installation and configuration for VPN server
# Supports: Ubuntu, Debian, CentOS, Fedora, RHEL, Arch Linux
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
echo "    WireGuard VPN Installation"
echo "=========================================="
echo ""

# Detect OS
if [[ -f /etc/os-release ]]; then
    . /etc/os-release
    OS=$ID
    VERSION=$VERSION_ID
else
    print_error "Cannot detect OS"
    exit 1
fi
print_info "Detected OS: $OS $VERSION"

# Install WireGuard
print_info "Installing WireGuard and dependencies..."
case $OS in
    ubuntu|debian)
        apt update -qq
        apt install -y wireguard wireguard-tools qrencode iptables curl
        ;;
    centos|rhel)
        if [[ $VERSION == 7* ]]; then
            yum install -y epel-release elrepo-release
            yum install -y kmod-wireguard wireguard-tools qrencode curl
        else
            dnf install -y wireguard-tools qrencode curl
        fi
        ;;
    fedora)
        dnf install -y wireguard-tools qrencode curl
        ;;
    arch|manjaro)
        pacman -Sy --noconfirm wireguard-tools qrencode curl
        ;;
    *)
        print_error "Unsupported distribution: $OS"
        exit 1
        ;;
esac
print_success "WireGuard installed successfully"

# Configuration variables
WG_DIR="/etc/wireguard"
WG_PORT="51820"
WG_SERVER_IP="10.0.0.1/24"
WG_CLIENT_IP="10.0.0.2/32"
CLIENT_NAME="client1"

# Generate server keys
print_info "Generating server keys..."
mkdir -p $WG_DIR
chmod 700 $WG_DIR

wg genkey | tee $WG_DIR/server_private.key | wg pubkey > $WG_DIR/server_public.key
chmod 600 $WG_DIR/server_private.key

SERVER_PRIVATE_KEY=$(cat $WG_DIR/server_private.key)
SERVER_PUBLIC_KEY=$(cat $WG_DIR/server_public.key)

print_info "Server public key: $SERVER_PUBLIC_KEY"

# Detect network interface
NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
if [[ -z $NETWORK_INTERFACE ]]; then
    print_error "Could not detect network interface"
    exit 1
fi
print_info "Network interface: $NETWORK_INTERFACE"

# Get public IP
print_info "Detecting server public IP..."
SERVER_PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || \
                   curl -s --max-time 5 icanhazip.com 2>/dev/null || \
                   curl -s --max-time 5 ipinfo.io/ip 2>/dev/null || \
                   curl -s --max-time 5 api.ipify.org 2>/dev/null)

if [[ -z $SERVER_PUBLIC_IP ]]; then
    print_error "Could not detect public IP automatically"
    read -p "Enter your server public IP address: " SERVER_PUBLIC_IP
    if [[ -z $SERVER_PUBLIC_IP ]]; then
        print_error "Public IP is required"
        exit 1
    fi
fi

print_info "Public IP: $SERVER_PUBLIC_IP"

# Create server configuration
print_info "Configuring WireGuard server..."
cat > $WG_DIR/wg0.conf <<EOF
[Interface]
Address = $WG_SERVER_IP
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE_KEY
SaveConfig = false

PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE

PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE

EOF

chmod 600 $WG_DIR/wg0.conf
print_success "Server configuration created"

# Enable IP forwarding
print_info "Enabling IP forwarding..."
if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
    echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
fi
sysctl -w net.ipv4.ip_forward=1 > /dev/null
print_success "IP forwarding enabled"

# Configure firewall
print_info "Configuring firewall..."
if command -v ufw &> /dev/null; then
    ufw allow $WG_PORT/udp > /dev/null 2>&1
    print_info "UFW rule added for port $WG_PORT/udp"
fi

if command -v firewall-cmd &> /dev/null; then
    firewall-cmd --permanent --add-port=$WG_PORT/udp > /dev/null 2>&1
    firewall-cmd --permanent --add-masquerade > /dev/null 2>&1
    firewall-cmd --reload > /dev/null 2>&1
    print_info "FirewallD rules added for port $WG_PORT/udp"
fi

# Start WireGuard
print_info "Starting WireGuard service..."
systemctl enable wg-quick@wg0 > /dev/null 2>&1
systemctl start wg-quick@wg0

sleep 2

if systemctl is-active --quiet wg-quick@wg0; then
    print_success "WireGuard service is running!"
else
    print_error "Failed to start WireGuard service"
    systemctl status wg-quick@wg0 --no-pager
    exit 1
fi

# Generate client configuration
print_info "Generating client configuration..."

CLIENT_DIR="$WG_DIR/clients"
mkdir -p $CLIENT_DIR

CLIENT_PRIVATE_KEY=$(wg genkey)
CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)

cat > $CLIENT_DIR/${CLIENT_NAME}.conf <<EOF
[Interface]
PrivateKey = $CLIENT_PRIVATE_KEY
Address = $WG_CLIENT_IP
DNS = 1.1.1.1, 8.8.8.8

[Peer]
PublicKey = $SERVER_PUBLIC_KEY
Endpoint = $SERVER_PUBLIC_IP:$WG_PORT
AllowedIPs = 0.0.0.0/0, ::/0
PersistentKeepalive = 25
EOF

# Add client to server
cat >> $WG_DIR/wg0.conf <<EOF

# Client: $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $WG_CLIENT_IP
EOF

systemctl restart wg-quick@wg0

print_success "Client configuration created!"

# Display results
echo ""
echo "=========================================="
print_success "Installation Complete!"
echo "=========================================="
echo ""

print_info "Server Status:"
wg show
echo ""

print_info "📋 Server Details:"
echo "  ├─ Public IP: $SERVER_PUBLIC_IP"
echo "  ├─ Listen Port: $WG_PORT (UDP)"
echo "  ├─ Server IP: $WG_SERVER_IP"
echo "  └─ Public Key: $SERVER_PUBLIC_KEY"
echo ""

print_info "📁 Client Configuration:"
echo "  ├─ File: $CLIENT_DIR/${CLIENT_NAME}.conf"
echo "  └─ Client IP: $WG_CLIENT_IP"
echo ""

# Generate QR code
if command -v qrencode &> /dev/null; then
    print_info "📱 QR Code for Mobile Devices:"
    echo ""
    qrencode -t ansiutf8 < $CLIENT_DIR/${CLIENT_NAME}.conf
    echo ""
else
    print_warning "Install 'qrencode' to generate QR codes: apt install qrencode"
fi

echo "=========================================="
print_info "Client Configuration File:"
echo "=========================================="
cat $CLIENT_DIR/${CLIENT_NAME}.conf
echo "=========================================="
echo ""

print_info "🔗 How to Connect Your Devices"
echo ""
echo "📱 ANDROID / iOS:"
echo "   1. Install 'WireGuard' app from Play Store/App Store"
echo "   2. Tap '+' button"
echo "   3. Select 'Scan from QR code' (if shown above)"
echo "   4. OR Select 'Import from file' and choose ${CLIENT_NAME}.conf"
echo "   5. Toggle the connection ON"
echo ""
echo "💻 WINDOWS:"
echo "   1. Download WireGuard: https://www.wireguard.com/install/"
echo "   2. Install and open WireGuard application"
echo "   3. Click 'Import tunnel(s) from file'"
echo "   4. Select: ${CLIENT_NAME}.conf"
echo "   5. Click 'Activate' button"
echo ""
echo "🐧 LINUX:"
echo "   1. Copy ${CLIENT_NAME}.conf to /etc/wireguard/"
echo "   2. Run: sudo wg-quick up ${CLIENT_NAME}"
echo "   3. Stop: sudo wg-quick down ${CLIENT_NAME}"
echo ""
echo "🍎 macOS:"
echo "   1. Install WireGuard from App Store"
echo "   2. Click 'Import tunnel(s) from file'"
echo "   3. Select ${CLIENT_NAME}.conf and activate"
echo ""

print_warning "⚠️  IMPORTANT - Firewall Configuration"
echo ""
echo "If using DigitalOcean, AWS, or other cloud provider:"
echo "  1. Open their web console"
echo "  2. Go to Firewall/Security Groups settings"
echo "  3. Add inbound rule: UDP port $WG_PORT"
echo "  4. Source: 0.0.0.0/0 (All IPv4) and ::/0 (All IPv6)"
echo ""

print_info "📝 Useful Commands:"
echo "   sudo systemctl status wg-quick@wg0  # Check service status"
echo "   sudo wg show                         # Show WireGuard status"
echo "   sudo systemctl restart wg-quick@wg0  # Restart service"
echo "   sudo journalctl -u wg-quick@wg0 -f   # View logs"
echo ""

print_info "📂 Configuration Files:"
echo "   Server config: $WG_DIR/wg0.conf"
echo "   Client config: $CLIENT_DIR/${CLIENT_NAME}.conf"
echo ""

print_success "✅ WireGuard VPN is ready to use!"
echo "   Download the client config and import it to your device"
echo ""
