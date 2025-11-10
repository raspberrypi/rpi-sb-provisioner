#!/bin/bash
# Setup script for nginx with PAM authentication
# Run this script with sudo from the nginx-example directory

set -e

# Get the directory where this script is located
SCRIPT_DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" && pwd )"
cd "$SCRIPT_DIR"

echo "=== Nginx PAM Authentication Setup ==="
echo "Working directory: $SCRIPT_DIR"
echo ""

# Check if running as root
if [ "$EUID" -ne 0 ]; then 
    echo "Please run as root (use sudo)"
    exit 1
fi

# Install nginx-extras if not already installed
echo "[1/5] Checking for nginx-extras package..."
if ! dpkg -l | grep -q nginx-extras; then
    echo "Installing nginx-extras..."
    apt-get update
    apt-get install -y nginx-extras
else
    echo "nginx-extras is already installed"
fi

# Create PAM configuration file
echo ""
echo "[2/5] Creating PAM configuration for nginx..."
if [ -f "pam.d-nginx" ]; then
    cp pam.d-nginx /etc/pam.d/nginx
    chmod 644 /etc/pam.d/nginx
    echo "Created /etc/pam.d/nginx"
else
    cat > /etc/pam.d/nginx << 'EOF'
# PAM configuration for nginx
@include common-auth
@include common-account
@include common-session
EOF
    chmod 644 /etc/pam.d/nginx
    echo "Created /etc/pam.d/nginx with default configuration"
fi

# Add nginx user to shadow group
echo ""
echo "[3/5] Adding www-data user to shadow group..."
usermod -a -G shadow www-data
echo "www-data added to shadow group"

# Copy nginx configuration
echo ""
echo "[4/5] Setting up nginx configuration..."
if [ -f "nginx-reverse-proxy.conf" ]; then
    cp nginx-reverse-proxy.conf /etc/nginx/sites-available/reverse-proxy-pam
    echo "Copied configuration to /etc/nginx/sites-available/reverse-proxy-pam"
    echo ""
    echo "IMPORTANT: You must edit the following in /etc/nginx/sites-available/reverse-proxy-pam:"
    echo "  - server_name directives (your-domain.com, your-domain-ssl.com)"
    echo "  - SSL certificate paths (ssl_certificate, ssl_certificate_key)"
    echo "  - Verify port 3143 backend protocol (http:// or https://)"
    echo ""
    read -p "Press Enter after you've edited the configuration file..."
    
    # Enable the site
    if [ ! -f "/etc/nginx/sites-enabled/reverse-proxy-pam" ]; then
        ln -s /etc/nginx/sites-available/reverse-proxy-pam /etc/nginx/sites-enabled/
        echo "Enabled nginx site configuration"
    fi
else
    echo "Warning: nginx-reverse-proxy.conf not found in current directory"
    echo "You'll need to manually copy the configuration"
fi

# Test nginx configuration
echo ""
echo "[5/5] Testing nginx configuration..."
if nginx -t; then
    echo ""
    echo "Configuration test passed!"
    echo ""
    read -p "Restart nginx to apply changes? (y/n): " -n 1 -r
    echo
    if [[ $REPLY =~ ^[Yy]$ ]]; then
        systemctl restart nginx
        echo "Nginx restarted successfully"
    fi
else
    echo ""
    echo "Configuration test failed. Please fix the errors before restarting nginx."
    exit 1
fi

echo ""
echo "=== Setup Complete ==="
echo ""
echo "Your services should now be accessible with PAM authentication:"
echo "  - http://your-domain.com (proxies to port 3142)"
echo "  - https://your-domain-ssl.com (proxies to port 3143)"
echo ""
echo "Users will be prompted for system username/password to access the services."
echo ""
echo "To test authentication, try accessing the service in a browser or with curl:"
echo "  curl -u username http://your-domain.com"
echo ""

