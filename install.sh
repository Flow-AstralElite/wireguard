#!/bin/bash

###############################################################################
# WireGuard Installation Script
# This script automates the installation and configuration of WireGuard VPN
# Supports: Ubuntu, Debian, CentOS, Fedora, Arch Linux
###############################################################################

set -e  # Exit on error

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

# Function to print colored output
print_info() {
    echo -e "${GREEN}[INFO]${NC} $1"
}

print_error() {
    echo -e "${RED}[ERROR]${NC} $1"
}

print_warning() {
    echo -e "${YELLOW}[WARNING]${NC} $1"
}

# Check if script is run as root
check_root() {
    if [[ $EUID -ne 0 ]]; then
        print_error "This script must be run as root"
        exit 1
    fi
}

# Detect Linux distribution
detect_os() {
    if [[ -f /etc/os-release ]]; then
        . /etc/os-release
        OS=$ID
        VERSION=$VERSION_ID
    else
        print_error "Cannot detect OS. /etc/os-release not found."
        exit 1
    fi
    print_info "Detected OS: $OS $VERSION"
}

# Install WireGuard based on distribution
install_wireguard() {
    print_info "Installing WireGuard..."
    
    case $OS in
        ubuntu|debian)
            apt update
            apt install -y wireguard wireguard-tools
            ;;
        centos|rhel)
            if [[ $VERSION == 7* ]]; then
                yum install -y epel-release elrepo-release
                yum install -y yum-plugin-elrepo
                yum install -y kmod-wireguard wireguard-tools
            else
                dnf install -y wireguard-tools
            fi
            ;;
        fedora)
            dnf install -y wireguard-tools
            ;;
        arch|manjaro)
            pacman -Sy --noconfirm wireguard-tools
            ;;
        *)
            print_error "Unsupported distribution: $OS"
            exit 1
            ;;
    esac
    
    print_info "WireGuard installed successfully"
}

# Generate server keys
generate_keys() {
    print_info "Generating WireGuard keys..."
    
    WG_DIR="/etc/wireguard"
    mkdir -p $WG_DIR
    chmod 700 $WG_DIR
    
    # Generate private and public keys
    wg genkey | tee $WG_DIR/server_private.key | wg pubkey > $WG_DIR/server_public.key
    chmod 600 $WG_DIR/server_private.key
    
    SERVER_PRIVATE_KEY=$(cat $WG_DIR/server_private.key)
    SERVER_PUBLIC_KEY=$(cat $WG_DIR/server_public.key)
    
    print_info "Server public key: $SERVER_PUBLIC_KEY"
}

# Get server network interface
get_network_interface() {
    # Try to detect the main network interface
    NETWORK_INTERFACE=$(ip route | grep default | awk '{print $5}' | head -n1)
    
    if [[ -z $NETWORK_INTERFACE ]]; then
        print_warning "Could not detect network interface automatically"
        read -p "Enter your network interface (e.g., eth0, ens3): " NETWORK_INTERFACE
    else
        print_info "Detected network interface: $NETWORK_INTERFACE"
        read -p "Press Enter to use $NETWORK_INTERFACE or type a different interface: " USER_INTERFACE
        if [[ ! -z $USER_INTERFACE ]]; then
            NETWORK_INTERFACE=$USER_INTERFACE
        fi
    fi
}

# Configure WireGuard server
configure_server() {
    print_info "Configuring WireGuard server..."
    
    # Get configuration parameters
    read -p "Enter WireGuard listen port [default: 51820]: " WG_PORT
    WG_PORT=${WG_PORT:-51820}
    
    read -p "Enter WireGuard server IP [default: 10.0.0.1/24]: " WG_SERVER_IP
    WG_SERVER_IP=${WG_SERVER_IP:-10.0.0.1/24}
    
    # Create server configuration
    cat > $WG_DIR/wg0.conf <<EOF
[Interface]
Address = $WG_SERVER_IP
ListenPort = $WG_PORT
PrivateKey = $SERVER_PRIVATE_KEY
SaveConfig = false

# Enable IP forwarding and NAT
PostUp = sysctl -w net.ipv4.ip_forward=1
PostUp = iptables -A FORWARD -i wg0 -j ACCEPT
PostUp = iptables -A FORWARD -o wg0 -j ACCEPT
PostUp = iptables -t nat -A POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE

PostDown = iptables -D FORWARD -i wg0 -j ACCEPT
PostDown = iptables -D FORWARD -o wg0 -j ACCEPT
PostDown = iptables -t nat -D POSTROUTING -o $NETWORK_INTERFACE -j MASQUERADE

EOF

    chmod 600 $WG_DIR/wg0.conf
    print_info "Server configuration created at $WG_DIR/wg0.conf"
}

# Enable IP forwarding
enable_ip_forwarding() {
    print_info "Enabling IP forwarding..."
    
    # Enable IP forwarding permanently
    if ! grep -q "^net.ipv4.ip_forward=1" /etc/sysctl.conf; then
        echo "net.ipv4.ip_forward=1" >> /etc/sysctl.conf
    fi
    sysctl -p
    
    print_info "IP forwarding enabled"
}

# Configure firewall
configure_firewall() {
    print_info "Configuring firewall..."
    
    # UFW (Ubuntu/Debian)
    if command -v ufw &> /dev/null; then
        ufw allow $WG_PORT/udp
        print_info "UFW firewall rule added for port $WG_PORT/udp"
    fi
    
    # FirewallD (CentOS/Fedora/RHEL)
    if command -v firewall-cmd &> /dev/null; then
        firewall-cmd --permanent --add-port=$WG_PORT/udp
        firewall-cmd --permanent --add-masquerade
        firewall-cmd --reload
        print_info "FirewallD rules added for port $WG_PORT/udp"
    fi
}

# Start and enable WireGuard service
start_wireguard() {
    print_info "Starting WireGuard service..."
    
    systemctl enable wg-quick@wg0
    systemctl start wg-quick@wg0
    
    if systemctl is-active --quiet wg-quick@wg0; then
        print_info "WireGuard service started successfully"
        print_info "Service status:"
        systemctl status wg-quick@wg0 --no-pager
    else
        print_error "Failed to start WireGuard service"
        exit 1
    fi
}

# Get server public IP
get_public_ip() {
    print_info "Detecting server public IP..."
    
    # Try multiple services to get public IP
    SERVER_PUBLIC_IP=$(curl -s --max-time 5 ifconfig.me 2>/dev/null || \
                       curl -s --max-time 5 icanhazip.com 2>/dev/null || \
                       curl -s --max-time 5 ipinfo.io/ip 2>/dev/null || \
                       curl -s --max-time 5 api.ipify.org 2>/dev/null)
    
    if [[ -z $SERVER_PUBLIC_IP ]]; then
        print_warning "Could not automatically detect public IP"
        read -p "Enter your server public IP address: " SERVER_PUBLIC_IP
        
        if [[ -z $SERVER_PUBLIC_IP ]]; then
            print_error "Public IP is required to generate client config"
            exit 1
        fi
    else
        print_info "Detected public IP: $SERVER_PUBLIC_IP"
        read -p "Press Enter to use $SERVER_PUBLIC_IP or type a different IP: " USER_IP
        if [[ ! -z $USER_IP ]]; then
            SERVER_PUBLIC_IP=$USER_IP
        fi
    fi
}

# Generate client configuration
generate_client_config() {
    print_info "Generating client configuration..."
    
    read -p "Enter client name: " CLIENT_NAME
    CLIENT_NAME=${CLIENT_NAME:-client1}
    
    read -p "Enter client IP [default: 10.0.0.2/32]: " CLIENT_IP
    CLIENT_IP=${CLIENT_IP:-10.0.0.2/32}
    
    # Generate client keys
    CLIENT_PRIVATE_KEY=$(wg genkey)
    CLIENT_PUBLIC_KEY=$(echo $CLIENT_PRIVATE_KEY | wg pubkey)
    
    # Create client config directory
    CLIENT_DIR="$WG_DIR/clients"
    mkdir -p $CLIENT_DIR
    
    # Create client configuration file
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

    # Add client to server configuration
    cat >> $WG_DIR/wg0.conf <<EOF

# Client: $CLIENT_NAME
[Peer]
PublicKey = $CLIENT_PUBLIC_KEY
AllowedIPs = $CLIENT_IP
EOF

    # Restart WireGuard to apply changes
    systemctl restart wg-quick@wg0
    
    print_info "Client configuration created: $CLIENT_DIR/${CLIENT_NAME}.conf"
    print_info "Client public key: $CLIENT_PUBLIC_KEY"
    
    # Generate QR code for mobile devices if qrencode is available
    if command -v qrencode &> /dev/null; then
        echo ""
        print_info "QR Code for Mobile Devices (scan with WireGuard app):"
        qrencode -t ansiutf8 < $CLIENT_DIR/${CLIENT_NAME}.conf
    else
        print_warning "Install 'qrencode' to generate QR codes for mobile devices"
        echo "  Ubuntu/Debian: apt install qrencode"
        echo "  CentOS/RHEL: yum install qrencode"
        echo "  Fedora: dnf install qrencode"
    fi
    
    echo ""
    print_info "Client configuration file content:"
    cat $CLIENT_DIR/${CLIENT_NAME}.conf
    
    # Instructions for connecting clients
    echo ""
    print_info "=========================================="
    print_info "How to Connect Your Devices:"
    print_info "=========================================="
    echo ""
    print_info "ANDROID / iOS:"
    echo "  1. Install 'WireGuard' app from Play Store / App Store"
    echo "  2. Open the app and tap '+' button"
    echo "  3. Select 'Create from QR code' (if QR code shown above)"
    echo "  4. OR Select 'Create from file or archive' and upload: ${CLIENT_NAME}.conf"
    echo "  5. Toggle the connection ON"
    echo ""
    print_info "WINDOWS:"
    echo "  1. Download WireGuard from: https://www.wireguard.com/install/"
    echo "  2. Install and open WireGuard application"
    echo "  3. Click 'Import tunnel(s) from file'"
    echo "  4. Select the file: $CLIENT_DIR/${CLIENT_NAME}.conf"
    echo "  5. Click 'Activate' to connect"
    echo ""
    print_info "LINUX:"
    echo "  1. Copy ${CLIENT_NAME}.conf to /etc/wireguard/"
    echo "  2. Run: sudo wg-quick up ${CLIENT_NAME}"
    echo "  3. To disconnect: sudo wg-quick down ${CLIENT_NAME}"
    echo ""
    print_info "macOS:"
    echo "  1. Download WireGuard from App Store"
    echo "  2. Open WireGuard app"
    echo "  3. Click 'Import tunnel(s) from file'"
    echo "  4. Select ${CLIENT_NAME}.conf and activate"
    echo ""
}

# Display summary
display_summary() {
    echo ""
    echo "=========================================="
    print_info "WireGuard Installation Complete!"
    echo "=========================================="
    echo ""
    print_info "Server Status:"
    wg show
    echo ""
    print_info "Configuration files location: $WG_DIR"
    print_info "Server public key: $SERVER_PUBLIC_KEY"
    print_info "Server public IP: $SERVER_PUBLIC_IP"
    print_info "Server listen port: $WG_PORT"
    echo ""
    print_info "To add more clients later, run this script again or manually:"
    echo "  1. Generate keys: wg genkey | tee client_private.key | wg pubkey > client_public.key"
    echo "  2. Add [Peer] section to $WG_DIR/wg0.conf"
    echo "  3. Restart: systemctl restart wg-quick@wg0"
    echo ""
    print_info "Useful commands:"
    echo "  - Check status: wg show"
    echo "  - Stop service: systemctl stop wg-quick@wg0"
    echo "  - Start service: systemctl start wg-quick@wg0"
    echo "  - Restart service: systemctl restart wg-quick@wg0"
    echo "  - View logs: journalctl -u wg-quick@wg0 -f"
    echo "  - Add client: $0 (run script again)"
    echo ""
    print_info "Client config files are saved in: $WG_DIR/clients/"
    echo ""
}

# Main installation flow
main() {
    clear
    echo "=========================================="
    echo "    WireGuard Installation Script"
    echo "=========================================="
    echo ""
    
    check_root
    detect_os
    install_wireguard
    generate_keys
    get_network_interface
    get_public_ip
    configure_server
    enable_ip_forwarding
    configure_firewall
    start_wireguard
    
    echo ""
    read -p "Do you want to generate a client configuration now? (y/n): " GENERATE_CLIENT
    if [[ $GENERATE_CLIENT == "y" || $GENERATE_CLIENT == "Y" ]]; then
        generate_client_config
    fi
    
    display_summary
}

# Run main function
main
