# API Documentation Structure

This directory contains the modular API documentation for the rpi-sb-provisioner service.

## Organization

The API documentation is split into logical sections for maintainability:

- [manufacturing.md](manufacturing.md) — Manufacturing Database API endpoints
- [devices.md](devices.md) — Device management and monitoring endpoints
- [customisation.md](customisation.md) — Customisation script management (CRUD operations)
- [qrcode.md](qrcode.md) — QR code verification endpoints
- [services.md](services.md) — Systemd service monitoring and logs
- [images.md](images.md) — OS image management and SHA256 calculation
- [configuration.md](configuration.md) — System configuration and firmware management
- [audit.md](audit.md) — Security audit log access
- [websockets.md](websockets.md) — Real-time WebSocket APIs
- [errors.md](errors.md) — Standard error response format and content negotiation

[../api_endpoints.md](../api_endpoints.md) serves as a navigation index that links to each sub-document.

## Editing

1. Locate the appropriate section file in this `api/` subdirectory.
2. Edit the relevant `.md` file.
3. Cross-references between documents use standard Markdown links, so GitHub renders them directly with no build step.

## Benefits

This modular structure provides:

- **Easier maintenance** — each API group is in its own file
- **Better organization** — clear separation of concerns
- **Faster editing** — smaller files are easier to navigate
- **Parallel editing** — multiple people can edit different sections simultaneously
