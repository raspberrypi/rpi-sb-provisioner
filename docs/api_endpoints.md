# HTTP API

The provisioner's web service, `rpi-provisioner-ui`, listens on port 3142 (HTTP) and 3143 (HTTPS) by default. Everything the web interface does goes through this API, so it can also drive dashboards, line tooling and scripts.

This page is an index only. Each section's endpoints, parameters, responses and errors are documented in [api/](api/), and nowhere else, so there is one copy to keep right.

Start with [Authentication](api/authentication.md): every endpoint except a few read-only dashboard pages needs an operator, by signed-in browser session or by API token (`Authorization: Bearer <token>`), and every state-changing endpoint is `POST`-only and needs the CSRF token unless a bearer token is used.

| Section | Covers |
|---------|--------|
| [Authentication](api/authentication.md) | Signing in and out, sessions, CSRF, API tokens, and why requests are refused |
| [Devices](api/devices.md) | Device state, logs, per-device flags and device key downloads |
| [Manufacturing](api/manufacturing.md) | Records of provisioned devices |
| [QR code](api/qrcode.md) | Checking a scanned code against the manufacturing records |
| [Customisation](api/customisation.md) | Hook scripts, and the arguments and environment each hook receives |
| [Images](api/images.md) | OS images and IDP artefacts: upload, delete, hashes, analysis, boot packages |
| [Configuration](api/configuration.md) | Settings, firmware, bootloader configuration, signing keys, HSM PINs, device key and workdir |
| [Services](api/services.md) | Provisioning services and their journal logs |
| [Audit log](api/audit.md) | Who did what: API access, file changes, sign-ins and tokens |
| [WebSockets](api/websockets.md) | Live device topology, hash progress, boot package status and upload progress |
| [Errors](api/errors.md) | The error body and content negotiation |

Settings are described in [config_vars.md](config_vars.md).
