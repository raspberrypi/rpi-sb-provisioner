# Authentication

Every endpoint requires an operator: a system account in the `rpi-sb-provisioner` group. The service runs as root, so operator access is root-equivalent; grant it as you would `sudo`.

The exceptions, unless `RPI_SB_PROVISIONER_PUBLIC_DASHBOARD` is turned off, are these `GET` (and `HEAD`) requests, which anyone may make:

- `/` and `/devices`, and `/ws/devices` for live updates;
- `/devices/<serial>` or `/devices/<usb-path>`, which then omits the device's logs and per-device overrides. Longer paths (logs, keys, flags) still need an operator;
- `/scantool` and `GET /api/v2/verify-qrcode`;
- `/auth/session`, which reports an empty user.

## In a browser

Open <http://localhost:3142> and sign in with your system username and password. A session lasts 12 hours, or 2 hours without use, and ends within a minute if the account leaves the group.

Pages sign each state-changing request with the session's CSRF token automatically. If you write your own page against the API, send the value of the `rpi_sb_csrf` cookie (or `csrfToken` from `/auth/session`) in an `X-CSRF-Token` header on every request that is not a `GET` or `HEAD`. A `_csrf_token` query parameter is accepted in its place.

Over plain HTTP, signing in from another machine is refused; use HTTPS. The session cookie is marked `Secure` when the browser used HTTPS, including through a local proxy that sends `X-Forwarded-Proto: https`.

## From a script

Create an API token under **API tokens** (click your username in the navigation bar), then send it as a bearer token:

``` bash
export RPI_SB_TOKEN=rpisb_...   # copied from the API tokens page
curl -H "Authorization: Bearer $RPI_SB_TOKEN" http://localhost:3142/api/v2/manufacturing
```

A token:

- starts `rpisb_` and acts as the operator who created it, and stops working if they leave the group;
- is shown once, when created. Only its SHA-256 hash is stored, in `/etc/rpi-sb-provisioner/api-tokens.json` (root-only);
- needs no CSRF token, because browsers never send an `Authorization` header by themselves. The request must still not come from another origin;
- cannot list, create or revoke tokens. That needs a signed-in browser, so a leaked token cannot mint more.

At most 64 tokens may exist at once.

Revoke a token from the same page when a script is retired or the token may have leaked.

## Requests that are refused

| Status | Code                     | Cause                                                                                   |
|--------|--------------------------|-----------------------------------------------------------------------------------------|
| 401    | `UNAUTHENTICATED`        | No session and no token. Browsers asking for HTML are redirected to `/login` instead.     |
| 401    | `INVALID_TOKEN`          | Unknown or revoked token, or its owner is no longer in the group.                        |
| 403    | `CSRF_VALIDATION_FAILED` | A browser-session write without the session's CSRF token.                                |
| 403    | `CROSS_ORIGIN`           | A write or WebSocket from another origin (`Origin` or `Sec-Fetch-Site` names another site). |
| 403    | `SESSION_REQUIRED`       | A token endpoint called with a bearer token.                                             |
| 411, 413 | —                      | On paths anyone may reach (`/login`, public pages), a chunked body or one over 64 KiB.   |
| 405    | —                        | A state-changing endpoint called with `GET`. They are all `POST`-only.                   |
| 421    | —                        | The `Host` header is not a name this machine answers to. Add one with `--allowed-host`.   |

These refusals use the body `{"error": "<code>", "message": "<text>"}`.

# Endpoints

## /login

**HTTP Method:** GET, POST

`GET` returns the sign-in page, or redirects (303) to `next` if already signed in. `POST` takes form fields `username` and `password`, and `next` in the query string, a path on this server to return to (default `/devices`).

On success: `303 See Other` to `next`, setting the `rpi_sb_session` cookie (HttpOnly) and the `rpi_sb_csrf` cookie, both `SameSite=Strict`. On failure the sign-in page is returned with:

| Status | Cause                                                                  |
|--------|------------------------------------------------------------------------|
| 400    | Username or password missing or too long                               |
| 401    | Wrong password, unknown account, or not in `rpi-sb-provisioner`; one message for all |
| 403    | Over plain HTTP from another machine                                   |
| 429    | Too many sign-in attempts in progress from the address                 |

Each failure takes at least two seconds. Every attempt is recorded in the [audit log](audit.md).

## /logout

**HTTP Method:** POST

Ends the session and clears both cookies, then redirects (303) to `next` if it can be seen without signing in, otherwise to `/devices`, or to `/login` when the public dashboard is off. Needs the CSRF token, like any other write.

## /auth/session

**HTTP Method:** GET

``` json
{ "user": "operator", "csrfToken": "9f2c..." }
```

Both are empty for a viewer who has not signed in, and `csrfToken` is empty for a bearer-token request. `/options/csrf-token` returns the same token as `{"token": "..."}`.

## /auth/tokens

**HTTP Method:** GET

The API tokens page (HTML).

## /api/v2/tokens

**HTTP Method:** GET, POST. Signed-in browser session only.

`GET` lists every token, without its secret:

``` json
[
  { "id": "1a2b3c4d", "user": "operator", "label": "line 3 dashboard", "created": "2026-10-07T08:00:00Z" }
]
```

`POST` creates one for the signed-in operator:

``` json
{ "label": "line 3 dashboard" }
```

``` json
{ "id": "1a2b3c4d", "token": "rpisb_..." }
```

The label must be text of 1–100 characters, not only spaces (`400 INVALID_LABEL`). `500 TOKEN_CREATE_FAILED` when, for example, 64 tokens already exist.

## /api/v2/tokens/{id}/revoke

**HTTP Method:** POST. Signed-in browser session only.

Revokes the token: `204 No Content`, or `404 TOKEN_NOT_FOUND`. Any operator may revoke any token.
