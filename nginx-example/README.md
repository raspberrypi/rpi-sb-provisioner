# Nginx Reverse Proxy Example Configuration

This directory contains **example configuration files** for setting up nginx as a reverse proxy with PAM authentication for the provisioner services. These files are **not included in the Debian package** and are provided as optional reference material for users who want to expose the provisioner services to the network.

## Contents

- **nginx-reverse-proxy.conf** - Complete nginx configuration with PAM authentication
- **pam.d-nginx** - PAM service configuration file
- **setup-nginx-pam-auth.sh** - Automated setup script
- **NGINX_PAM_AUTH_README.md** - Detailed documentation

## Purpose

The rpi-sb-provisioner services run on localhost ports 3142 and 3143. This nginx configuration allows you to:

1. **Expose services to the network** - Make them accessible from other machines
2. **Add authentication** - Require system user credentials via HTTP Basic Auth
3. **Provide HTTPS** - Encrypt traffic with SSL/TLS
4. **Centralized access control** - Manage who can access the provisioner UI

## Quick Start

```bash
cd nginx-example
sudo ./setup-nginx-pam-auth.sh
```

For detailed instructions, see [NGINX_PAM_AUTH_README.md](NGINX_PAM_AUTH_README.md).

## Important Notes

- **Not required** - The provisioner works perfectly without nginx (localhost access only)
- **Security consideration** - Only expose the provisioner to trusted networks
- **Customization required** - You must edit the configuration with your domains/IPs and SSL certificates
- **Not packaged** - These files are examples only and are not installed by the .deb package

## When to Use This

Use this configuration if you need to:
- Access the provisioner UI from multiple machines
- Provide centralized authentication
- Add SSL/TLS encryption
- Control access via system user accounts

## When NOT to Use This

Don't use this if:
- You only access the provisioner from localhost
- You're in a development/testing environment
- You don't want to expose services to the network

## Support

This is example/reference material. The nginx configuration is not officially supported as part of the rpi-sb-provisioner package, but is provided as a convenience for common deployment scenarios.

For questions about the provisioner itself, see the main [README](../README.adoc).

