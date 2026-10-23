# Error responses

Most endpoints report errors with this JSON body:

``` json
{
  "error": "Image not found",
  "error_code": "IMAGE_NOT_FOUND",
  "details": "Optional technical detail"
}
```

| Field        | Description                                                  |
|--------------|--------------------------------------------------------------|
| `error`      | Human-readable message                                       |
| `error_code` | Machine-readable code; omitted by a few older handlers       |
| `details`    | Further context, when there is any                           |

Some endpoints use their own shape, documented with each endpoint. In particular, requests refused before they reach a handler (see [authentication.md](authentication.md#requests-that-are-refused)) and the API token endpoints answer with:

``` json
{
  "error": "CSRF_VALIDATION_FAILED",
  "message": "Invalid or expired security token. Please refresh the page and try again."
}
```

Here `error` is the machine-readable code and `message` the human-readable text.

# Content negotiation

Endpoints that report errors with the body above return an HTML error page instead when the request's `Accept` header contains `text/html`. Otherwise, including when there is no `Accept` header, they return JSON.

A few endpoints, such as `/devices` and `/auditlog`, also return their HTML page for `Accept: text/html` and JSON otherwise; each says so in its own section.
