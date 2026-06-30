This document describes the API endpoints available in the provisioner-service. These endpoints can be used for integration with other systems, building custom dashboards, or automating operations.

The API documentation is organized into the following sections. Click on any section to view the detailed documentation.

# Core API Sections

## [Manufacturing Database API](api/manufacturing.md)

Access device provisioning records and manufacturing data collected during the provisioning process. Provides pagination support and detailed device information including hardware specifications, security settings, and provisioning timestamps.

**Key Endpoints:**

- `GET /api/v2/manufacturing` - Retrieve manufacturing database records with optional filtering

**Use Cases:** Building custom dashboards, integration with inventory systems, quality assurance tracking

## [Devices API](api/devices.md)

Monitor and manage devices during provisioning, including access to device logs and cryptographic keys. Provides detailed information about device state, IP addresses, and USB topology.

**Key Endpoints:**

- `GET /devices` - List all devices

- `GET /devices/{serialno}` - Get device details

- `GET /devices/{serialno}/log/{type}` - Retrieve device logs (provisioner, bootstrap, triage)

- `GET /devices/{serialno}/key/public` - Download public key

- `GET /devices/{serialno}/key/private` - Download private key (DISABLED BY DEFAULT - see security documentation)

**Use Cases:** Real-time device monitoring, log retrieval for troubleshooting, key management

> **Caution**
>
> The private key download endpoint is disabled by default for security reasons. See the Devices API documentation for details on the security configuration required to enable it.

## [Customisation API](api/customisation.md)

Full CRUD (Create, Read, Update, Delete) operations for managing customisation scripts that hook into various provisioning stages. Scripts can customize device configuration during bootstrap, filesystem mounting, and post-flash stages.

**Key Endpoints:**

- `GET /customisation/list-scripts` - List all scripts and hook points

- `GET /customisation/get-script` - Retrieve script content

- `POST /customisation/save-script` - Create or update scripts

- `POST /customisation/upload-script` - Upload script files

- `POST /customisation/enable-script` - Enable script execution

- `POST /customisation/disable-script` - Disable script execution

- `POST /customisation/delete-script` - Delete scripts

- `GET /customisation/list-hooks` - List all available hook points

- `GET /customisation/create-script` - Get template for new scripts

**Use Cases:** Automated device customisation, deployment-specific configuration, fleet management

## [QR Code Verification API](api/qrcode.md)

Verify QR codes against the manufacturing database for device validation and quality control during the scanning process.

**Key Endpoints:**

- `POST /api/v2/verify-qrcode` - Verify if a QR code exists in the manufacturing database

**Use Cases:** Barcode scanner integration, mobile app validation, quality control workflows

## [Services API](api/services.md)

Monitor provisioning services running on the system, retrieve service logs with pagination, and track service execution history through systemd journal integration.

**Key Endpoints:**

- `GET /api/v2/services` - List all provisioning services

- `GET /api/v2/service-log/{name}` - Retrieve service logs with pagination

**Use Cases:** Service monitoring, troubleshooting provisioning issues, historical service analysis

## [Images API](api/images.md)

Complete lifecycle management of OS images and IDP artefacts, including upload, download, metadata retrieval, asynchronous SHA256 hash calculation, and IDP descriptor analysis.

**Key Endpoints:**

- `GET /get-images` - List all available images

- `GET /get-image-metadata` - Get image metadata (size, modification time, etc.)

- `GET /get-image-sha256` - Calculate or retrieve SHA256 hash

- `POST /upload-image` - Upload new OS images

- `POST /delete-image` - Delete images

- `GET /analyze-image` - Analyze traditional images or IDP artefact directories

**Use Cases:** Image management, integrity verification, automated image deployment

## [Configuration API](api/configuration.md)

Manage system configuration options, firmware selection for different device families, key/HSM settings, secret wrapping status, and working directory management.

**Key Endpoints:**

- `GET /options/get` - Retrieve all configuration values

- `POST /options/set` - Update configuration

- `POST /options/validate` - Validate a configuration field

- `POST /options/upload-key` - Upload and validate a PEM signing key

- `GET /options/keys` - List saved signing keys and the active key

- `POST /options/keys/activate` - Activate a saved signing key

- `POST /options/keys/remove` - Remove a saved signing key

- `POST /options/keys/register-pkcs11` - Add a PKCS#11 key to the registry

- `POST /options/keys/wrap` - Device-wrap a saved PEM key at rest

- `POST /options/validate-key` - Validate PEM or PKCS#11 signing keys

- `GET /options/pkcs11-status` - Check OpenSSL PKCS#11 provider readiness

- `POST /options/pkcs11-discover` - Discover HSM key objects through p11-kit

- `GET /options/pkcs11-pin-status` - Check whether an HSM PIN is stored

- `POST /options/set-pkcs11-pin` - Store or remove an HSM PIN

- `GET /options/encryption-status` - Report device-wrapped secret status

- `POST /options/migrate-secrets` - Device-wrap previously plaintext stored secrets

- `POST /options/clear-workdir` - Clear working directory contents

- `GET /options/firmware` - List available firmware versions

- `POST /options/firmware/set` - Set firmware version

- `GET /options/firmware/notes/{version}` - Get firmware release notes

**Use Cases:** Configuration management, firmware updates, system administration

## [Audit Log API](api/audit.md)

Access security audit logs that track all system access, file operations, and sensitive actions. Supports filtering by event type, date range, and includes detailed client information.

**Key Endpoints:**

- `GET /auditlog` - Query audit logs with filtering

**Use Cases:** Security monitoring, compliance auditing, incident investigation

## [WebSocket APIs](api/websockets.md)

Real-time bidirectional communication for device topology updates and long-running operations like SHA256 hash calculations.

**Key Endpoints:**

- `WS /ws/devices` - Real-time device topology and provisioning status

- `WS /ws/sha256` - Real-time SHA256 calculation progress

**Use Cases:** Live dashboards, progress monitoring, real-time device tracking

## [Error Handling & Content Negotiation](api/errors.md)

Standard error response format used across all endpoints, plus information about content negotiation between JSON and HTML responses.

**Topics Covered:**

- Standard error response format

- HTTP status codes

- Error codes and meanings

- Content negotiation (`Accept` header handling)

**Use Cases:** Error handling in client applications, debugging API issues

# Additional Resources

- [Configuration Variables](config_vars.md) - Complete reference for all configuration options

- [API Documentation Structure](api/README.md) - Information about how the documentation is organized

# Quick Start

For most integrations, you’ll want to start with:

1.  [Devices API](api/devices.md) - Monitor device provisioning status

2.  [Manufacturing Database API](api/manufacturing.md) - Access provisioned device records

3.  [Services API](api/services.md) - Monitor service execution

For advanced customisation:

1.  [Customisation API](api/customisation.md) - Manage provisioning scripts

2.  [Images API](api/images.md) - Manage OS images

3.  [Configuration API](api/configuration.md) - System configuration
