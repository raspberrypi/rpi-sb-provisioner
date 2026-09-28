# Authentication

Every endpoint requires an operator: a system account in the `rpi-sb-provisioner` group. The service runs as root, so operator access is root-equivalent; grant it as you would `sudo`.

## In a browser

Open <http://localhost:3142> and sign in with your system username and password. A session lasts 12 hours, or 2 hours without use, and ends within a minute if the account leaves the group.

Pages sign each state-changing request with the session's CSRF token automatically. If you write your own page against the API, send the value of the `rpi_sb_csrf` cookie in an `X-CSRF-Token` header on every request that is not a `GET`.

## From a script

Create an API token under **API tokens** (click your username in the navigation bar), then send it as a bearer token:

``` bash
export RPI_SB_TOKEN=rpisb_...   # copied from the API tokens page
curl -H "Authorization: Bearer $RPI_SB_TOKEN" http://localhost:3142/api/v2/manufacturing
```

A token:

- acts as the operator who created it, and stops working if they leave the group;
- is shown once, when created. Only its SHA-256 hash is stored, in `/etc/rpi-sb-provisioner/api-tokens.json` (root-only);
- needs no CSRF token, because browsers never send an `Authorization` header by themselves;
- cannot create or revoke tokens. That needs a signed-in browser, so a leaked token cannot mint more.

Revoke a token from the same page when a script is retired or the token may have leaked.

## Requests that are refused

| Status | Code                     | Cause                                                                                   |
|--------|--------------------------|-----------------------------------------------------------------------------------------|
| 401    | `UNAUTHENTICATED`        | No session and no token. Browsers asking for HTML are redirected to `/login` instead.     |
| 401    | `INVALID_TOKEN`          | Unknown or revoked token, or its owner is no longer in the group.                        |
| 403    | `CSRF_VALIDATION_FAILED` | A browser-session write without the session's CSRF token.                                |
| 403    | `CROSS_ORIGIN`           | A write or WebSocket from another origin (`Origin` or `Sec-Fetch-Site` names another site). |
| 405    | —                        | A state-changing endpoint called with `GET`. They are all `POST`-only.                   |
| 421    | —                        | The `Host` header is not a name this machine answers to. Add one with `--allowed-host`.   |
