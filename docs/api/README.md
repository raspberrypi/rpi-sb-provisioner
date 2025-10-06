# API Documentation Structure

This directory contains the modular API documentation for the rpi-sb-provisioner service.

## Organization

The API documentation is split into logical sections for maintainability:

- **manufacturing.adoc** - Manufacturing Database API endpoints
- **devices.adoc** - Device management and monitoring endpoints
- **customisation.adoc** - Customisation script management (CRUD operations)
- **qrcode.adoc** - QR code verification endpoints
- **services.adoc** - Systemd service monitoring and logs
- **images.adoc** - OS image management and SHA256 calculation
- **configuration.adoc** - System configuration and firmware management
- **audit.adoc** - Security audit log access
- **websockets.adoc** - Real-time WebSocket APIs
- **errors.adoc** - Standard error response format and content negotiation

## Usage

The main documentation file `../api_endpoints.adoc` serves as a navigation index that links to each sub-document. This allows users to quickly browse available APIs and click through to detailed documentation for specific sections.

### Generating HTML Documentation

To generate HTML documentation (recommended):

```bash
# From the docs directory
cd docs

# Generate the main index page
asciidoctor api_endpoints.adoc

# Generate all individual API section pages
asciidoctor api/manufacturing.adoc
asciidoctor api/devices.adoc
asciidoctor api/customisation.adoc
asciidoctor api/qrcode.adoc
asciidoctor api/services.adoc
asciidoctor api/images.adoc
asciidoctor api/configuration.adoc
asciidoctor api/audit.adoc
asciidoctor api/websockets.adoc
asciidoctor api/errors.adoc

# Or generate all at once
asciidoctor api_endpoints.adoc api/*.adoc
```

The resulting HTML files will have working hyperlinks between pages.

### Generating a Combined PDF

If you need a single PDF with all documentation:

```bash
# From the docs directory
cd docs

# Option 1: Generate individual PDFs for each section
asciidoctor-pdf api/manufacturing.adoc
asciidoctor-pdf api/devices.adoc
# ... etc for each section

# Option 2: Create a temporary combined file with includes
# (You would need to temporarily change links back to includes)
```

**Note:** The link-based structure is optimized for HTML documentation. For a single combined PDF, you may need to create a separate build file that uses `include::` directives instead of `link:` directives.

### Viewing the Documentation

After generating HTML:

```bash
# Open the main index in your browser
xdg-open api_endpoints.html  # Linux
open api_endpoints.html       # macOS
start api_endpoints.html      # Windows
```

## Editing

When editing the API documentation:

1. Locate the appropriate section file in the `api/` subdirectory
2. Edit the relevant `.adoc` file
3. Regenerate the HTML files to see your changes
4. Links in `api_endpoints.adoc` will automatically navigate to the updated sections

## Benefits

This modular structure provides:

- **Easier maintenance** - Each API group is in its own file
- **Better organization** - Clear separation of concerns
- **Faster editing** - Smaller files are easier to navigate
- **Parallel editing** - Multiple people can edit different sections simultaneously
- **Reusability** - Individual sections can be included in other documents

