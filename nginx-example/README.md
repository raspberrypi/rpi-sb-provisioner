# nginx reverse proxy example

An example of putting nginx in front of the provisioner's web interface, so that it can be reached from other machines over HTTPS. These files are not included in the Debian package.

You don't need this if you only use the web interface on the provisioning machine itself.

## How it works

The web interface does its own sign-in. Operators use a system account that is a member of the `rpi-sb-provisioner` group, and scripts use API tokens (see [docs/api/authentication.md](../docs/api/authentication.md)). nginx adds nothing to that; it only provides HTTPS, so that passwords and session cookies never cross the network unencrypted.

The web interface keeps listening on `127.0.0.1` only, and nginx is the one thing that talks to it.

## Setting it up

1. Install nginx:

       sudo apt install nginx

2. Copy [nginx-reverse-proxy.conf](nginx-reverse-proxy.conf) to `/etc/nginx/sites-available/rpi-provisioner-ui`. Replace `provisioner.example.com` with the name people will use, and point `ssl_certificate` and `ssl_certificate_key` at a certificate for that name. Then enable it:

       sudo ln -s /etc/nginx/sites-available/rpi-provisioner-ui /etc/nginx/sites-enabled/
       sudo nginx -t && sudo systemctl reload nginx

3. Tell the web interface to answer to that name. It refuses requests addressed to names it doesn't know, which stops other websites reaching it through DNS rebinding:

       sudo systemctl edit rpi-provisioner-ui

   and add:

       [Service]
       ExecStart=
       ExecStart=/usr/bin/rpi-provisioner-ui --allowed-host provisioner.example.com

   Then restart it:

       sudo systemctl restart rpi-provisioner-ui

4. Browse to `https://provisioner.example.com` and sign in.

## Things to avoid

- **Plain HTTP.** The example redirects port 80 to HTTPS. Don't proxy port 80 through to the web interface: it would accept sign-ins sent unencrypted, because every request reaches it from nginx on loopback.
- **Authentication in nginx.** Earlier versions of this example put HTTP Basic authentication in nginx, checked against PAM, and added `www-data` to the `shadow` group. That let any account on the machine through and let nginx read every password hash. If you set that up, undo it:

      sudo gpasswd -d www-data shadow
      sudo rm /etc/pam.d/nginx

  Then remove the `auth_pam` lines from your nginx site.
- **Listening on the network directly.** Running the web interface with `--address 0.0.0.0` bypasses this proxy.
