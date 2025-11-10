# Nginx Reverse Proxy with PAM Authentication

This configuration sets up nginx as a reverse proxy for services on ports 3142 (HTTP) and 3143 (HTTPS) with HTTP Basic Authentication verified against system PAM accounts.

## Files Included

- **nginx-reverse-proxy.conf** - Main nginx configuration with PAM authentication
- **pam.d-nginx** - PAM service configuration file
- **setup-nginx-pam-auth.sh** - Automated setup script
- **NGINX_PAM_AUTH_README.md** - This documentation

## Quick Setup (Automated)

```bash
sudo ./setup-nginx-pam-auth.sh
```

The script will:
1. Install `nginx-extras` package (required for PAM module)
2. Create PAM configuration at `/etc/pam.d/nginx`
3. Add www-data user to shadow group (to read /etc/shadow)
4. Copy and enable nginx configuration
5. Test configuration and optionally restart nginx

## Manual Setup

### 1. Install nginx-extras

```bash
sudo apt-get update
sudo apt-get install nginx-extras
```

The standard nginx package doesn't include the PAM authentication module. You need `nginx-extras` which includes `ngx_http_auth_pam_module`.

### 2. Create PAM Configuration

Copy the PAM configuration file:

```bash
sudo cp pam.d-nginx /etc/pam.d/nginx
sudo chmod 644 /etc/pam.d/nginx
```

Or create it manually at `/etc/pam.d/nginx`:

```
@include common-auth
@include common-account
@include common-session
```

### 3. Grant nginx Permission to Read Shadow File

Add the nginx user (typically `www-data`) to the shadow group:

```bash
sudo usermod -a -G shadow www-data
```

This allows nginx to verify passwords against `/etc/shadow`.

### 4. Configure nginx

Edit `nginx-reverse-proxy.conf` and update:
- `server_name` directives with your actual domain or IP
- SSL certificate paths (`ssl_certificate` and `ssl_certificate_key`)
- Backend protocol for port 3143 (verify if it's `http://` or `https://`)

Then copy to nginx:

```bash
sudo cp nginx-reverse-proxy.conf /etc/nginx/sites-available/reverse-proxy-pam
sudo ln -s /etc/nginx/sites-available/reverse-proxy-pam /etc/nginx/sites-enabled/
```

### 5. Test and Restart

```bash
sudo nginx -t
sudo systemctl restart nginx
```

## Configuration Details

### Authentication

Both services (ports 3142 and 3143) are protected with HTTP Basic Authentication:

```nginx
auth_pam "Restricted Access - Login Required";
auth_pam_service_name "nginx";
```

Users must authenticate with their system username and password (same credentials used for SSH).

### Authenticated User Information

The authenticated username is passed to the backend service via the `X-Forwarded-User` header:

```nginx
proxy_set_header X-Forwarded-User $remote_user;
```

Your backend application can read this header to identify the logged-in user.

## Restricting Access to Specific Users

If you want to limit access to specific users only (rather than all system users):

1. Create a file with allowed usernames:

```bash
sudo mkdir -p /etc/nginx
sudo nano /etc/nginx/allowed_users
```

Add one username per line:
```
alice
bob
charlie
```

2. Modify `/etc/pam.d/nginx`:

```
auth required pam_listfile.so onerr=fail item=user sense=allow file=/etc/nginx/allowed_users
@include common-account
@include common-session
```

## Testing Authentication

### Using curl

```bash
# You'll be prompted for password
curl -u username http://your-domain.com

# Or provide password inline (not recommended for production)
curl -u username:password http://your-domain.com
```

### Using a Browser

Navigate to `http://your-domain.com` or `https://your-domain-ssl.com` in your browser. You'll see a login dialog prompting for username and password.

## Security Considerations

1. **Use HTTPS**: For production, always use HTTPS to prevent credentials from being sent in cleartext. Consider redirecting HTTP to HTTPS.

2. **SSL Certificates**: Use proper SSL certificates from Let's Encrypt or a trusted CA. Self-signed certificates should only be used for testing.

3. **Strong Passwords**: Ensure users have strong passwords since these are system accounts.

4. **Firewall**: Consider using a firewall to limit access to your services:
   ```bash
   sudo ufw allow 80/tcp
   sudo ufw allow 443/tcp
   sudo ufw enable
   ```

5. **Rate Limiting**: Add rate limiting to prevent brute force attacks:
   ```nginx
   limit_req_zone $binary_remote_addr zone=login:10m rate=5r/m;
   
   location / {
       limit_req zone=login burst=2 nodelay;
       auth_pam "Restricted Access - Login Required";
       # ... rest of config
   }
   ```

6. **Fail2ban**: Consider setting up fail2ban to block IPs after failed authentication attempts.

## Troubleshooting

### Authentication always fails

1. Check nginx error log:
   ```bash
   sudo tail -f /var/log/nginx/error.log
   ```

2. Verify www-data is in shadow group:
   ```bash
   groups www-data
   ```

3. Check PAM configuration:
   ```bash
   cat /etc/pam.d/nginx
   ```

4. Test PAM directly:
   ```bash
   sudo pamtester nginx username authenticate
   ```

### nginx fails to start

1. Check configuration syntax:
   ```bash
   sudo nginx -t
   ```

2. Verify nginx-extras is installed:
   ```bash
   nginx -V 2>&1 | grep auth_pam
   ```
   Should show `--with-http_auth_pam_module`

### Permission denied errors

Ensure www-data can read shadow file:
```bash
sudo ls -la /etc/shadow
sudo usermod -a -G shadow www-data
sudo systemctl restart nginx
```

## Alternative: LDAP Authentication

If you want to authenticate against LDAP instead of PAM, you can use the `nginx-auth-ldap` module. This requires compiling nginx with the module or using a pre-built package.

## Removing Authentication

To disable authentication temporarily, comment out the auth_pam lines in the nginx configuration:

```nginx
# auth_pam "Restricted Access - Login Required";
# auth_pam_service_name "nginx";
```

Then reload nginx:
```bash
sudo systemctl reload nginx
```

## Support

For issues with:
- **nginx configuration**: Check nginx documentation at https://nginx.org/en/docs/
- **PAM configuration**: See `man pam.conf` and PAM documentation
- **nginx-extras package**: Check your distribution's package repository

## License

This configuration is provided as-is for educational and production use.

