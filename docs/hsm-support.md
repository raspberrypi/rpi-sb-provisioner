# PKCS#11 / HSM Support

`rpi-sb-provisioner` can sign secure-boot artefacts with a private key held on a
PKCS#11 token or Hardware Security Module (HSM), instead of an on-disk PEM key.
The key never leaves the token: the provisioner sends it data to sign and
receives a signature back.

This guide covers what is supported, what an HSM must provide, how the token PIN
is handled, how to make a token available, and how to validate a setup before
you rely on it. For the `CUSTOMER_KEY_PKCS11_NAME` config variable itself, see
the [Configuration Reference](config_vars.md#customer_key_pkcs11_name).

---

## How it works

Signing goes through a standard, vendor-neutral stack:

```
rpi-sb-provisioner  →  OpenSSL 3 pkcs11-provider  →  p11-kit  →  vendor PKCS#11 module (.so)  →  HSM / token
```

- The provisioner (both the WebUI's key-validation path and the
  `rpi-sb-keyhelper` signing helper) loads the OpenSSL 3 **`pkcs11-provider`**
  into a private library context and resolves the configured `pkcs11:` URI
  through OpenSSL's `OSSL_STORE`.
- The `pkcs11-provider` discovers tokens through **[p11-kit](https://p11-glue.github.io/p11-glue/)**,
  which enumerates every PKCS#11 module registered on the host.
- Your **vendor's PKCS#11 module** (a shared library) does the actual talking to
  the token.

Two consequences follow from this design:

1. **It is not tied to any one vendor.** Anything that ships a standard PKCS#11
   v2.x+ module p11-kit can load should work — the provisioner speaks
   [RFC 7512](https://www.rfc-editor.org/rfc/rfc7512) `pkcs11:` URIs, not a
   vendor SDK.
2. **It does not use the deprecated OpenSSL ENGINE path** (`libp11` /
   `-engine pkcs11`). No `openssl.cnf` changes are required or read for token
   discovery (see [Configuration is via p11-kit, not openssl.cnf](#configuration-is-via-p11-kit-not-opensslcnf)).

> **Note**
>
> This refactor did not change the compatibility surface: the helper uses the
> same provider stack the provisioner has always used, driven programmatically.

---

## Requirements

An HSM/token must satisfy all of the following to be usable for Pi secure boot:

| Requirement | Detail |
| --- | --- |
| **RSA-2048 key** | Raspberry Pi secure boot requires a 2048-bit RSA key. Keys that are EC, or RSA of any other size (1024/3072/4096), are reported as *not fit for purpose* and rejected. This is a device constraint, not an HSM one. |
| **RSA PKCS#1 v1.5 signing** | The token must support `CKM_SHA256_RSA_PKCS` (or `CKM_RSA_PKCS` over a SHA-256 DigestInfo). This is near-universal. |
| **PKCS#11 module loadable by p11-kit** | A PKCS#11 v2.x+ `.so` that p11-kit can enumerate. |
| **User-PIN login (`CKU_USER`)** | The provisioner logs in with a single user PIN supplied in-process (see [PIN handling](#pin-handling-and-security)). |

Host-side software (already declared as package dependencies):

- **`pkcs11-provider`** — the OpenSSL 3 provider. Without it, the provisioner
  reports *"PKCS#11 provider not installed"* and PKCS#11 signing is unavailable.
- **`p11-kit`** (`libp11-kit`) — module discovery.
- **`gnutls-bin`** — provides `p11tool`, used below to inspect tokens.

---

## Compatibility

Because the provisioner relies only on the standard PKCS#11 + p11-kit + OpenSSL
`pkcs11-provider` stack, the following families are expected to work once their
module is registered with p11-kit and they hold an RSA-2048 key. This list is
illustrative, not a certification:

- **SoftHSM2** — software token, ideal for testing (see the [smoke test](#validating-a-setup-softhsm2-smoke-test)).
- **YubiKey / Nitrokey** (PIV applet) — note the PIV slot must hold an RSA-2048 key.
- **Network / enterprise HSMs** — Thales Luna, Entrust nShield, Utimaco, and similar.
- **Cloud HSMs via their PKCS#11 module** — e.g. AWS CloudHSM, Google Cloud HSM
  (`libkmsp11`). See the caveat on [credential-based modules](#what-is-not-supported).

If your token exposes a standard PKCS#11 module and an RSA-2048 key, it is very
likely to work even if it is not named here. Validate it with the
[smoke test](#validating-a-setup-softhsm2-smoke-test) before relying on it.

### What is *not* supported

These are genuine limitations to be aware of:

- **Non-RSA-2048 keys** — rejected as unfit (a Pi secure-boot constraint).
- **Non-PIN authentication flows** — external PIN-pad readers, security-officer-only
  (`CKU_SO`) login, or challenge/response schemes. The provisioner supplies a
  single user PIN; it cannot drive an interactive or out-of-band auth flow.
  (Keys flagged `CKA_ALWAYS_AUTHENTICATE`, which re-prompt on every signature,
  *are* handled — the same PIN is re-supplied on each prompt.)
- **Modules whose "credential" is not a PKCS#11 PIN** — some cloud modules take
  credentials via environment variables or a config file rather than the
  PKCS#11 user PIN. Those work, but you configure the credential the vendor's
  way; the WebUI-stored PIN is not what authenticates you.
- **Tokens that only work with provider quirks** — the `pkcs11-provider` has
  tuning options (e.g. `pkcs11-module-quirks`, login-behaviour settings) for
  unusual tokens. Because the provisioner loads the provider into a private
  context and does not read `openssl.cnf` (see below), such quirks are not
  currently wired in. Standard tokens do not need them.

### Configuration is via p11-kit, not openssl.cnf

The provisioner loads the `pkcs11-provider` into a **private** OpenSSL library
context and deliberately does **not** consult the system `openssl.cnf`. This
keeps the provider off the process-wide default context and removes any
dependency on system-wide OpenSSL configuration.

The practical implication: a token configured *only* through an `openssl.cnf`
`[pkcs11_sect]` provider block will **not** be discovered here. Registration
**must** be done with p11-kit (below). This is the supported and more robust
path.

---

## Making your HSM available

Register your vendor's PKCS#11 module with p11-kit by dropping a one-line module
file into `/usr/share/p11-kit/modules/` (for example `myhsm.module`):

```
module: /usr/lib/aarch64-linux-gnu/libmyhsm-pkcs11.so
```

Replace the path with your vendor's PKCS#11 driver library. That is the only
system configuration step — the provisioner needs no changes to `openssl.cnf`.

Confirm the token is discoverable, and find the object alias for your
`CUSTOMER_KEY_PKCS11_NAME` URI, with `p11tool` (from `gnutls-bin`):

```sh
# List the tokens p11-kit can see
p11tool --list-tokens

# List the keys on your token (use a token URI from the command above)
p11tool --login --list-all 'pkcs11:token=<your-token-label>'
```

The `CUSTOMER_KEY_PKCS11_NAME` value then takes the form:

```
'pkcs11:object=<keypair-alias>;type=private'
```

> **Warning**
>
> Enclose the value in single quotes and percent-encode any reserved characters
> in the object label — for example a label `SIGN key` becomes `SIGN%20key`.

---

## PIN handling and security

If the token requires a PIN, store it through the WebUI
(**Save PIN & Validate**). What happens then:

- The PIN is **device-wrapped at rest** — encrypted with a key derived from the
  provisioning Raspberry Pi's firmware crypto device key, so a stolen disk image
  or backup yields only ciphertext. It is stored at
  `/etc/rpi-sb-provisioner/keys/pkcs11.pin`.
- This requires the host to **have** a device key. It is not programmed at the
  factory, so a station that has only ever been imaged for provisioning may not
  have one, and saving a PIN will be refused until it does. The Options page
  reports this and offers to generate one; see
  [the host device key](architecture.md#the-host-device-key). Generating writes
  OTP permanently.
- At both key-validation and provisioning-time signing, the PIN is **unwrapped
  in process memory** and handed to the `pkcs11-provider` via OpenSSL's
  passphrase callback (inside `rpi-sb-keyhelper`). It **never** appears on a
  command line (visible in `ps`) or in a `pin-source=` file on disk.
- You do **not** need to add any PIN attribute to `CUSTOMER_KEY_PKCS11_NAME`
  when the WebUI holds the PIN.

**Managing the PIN outside the provisioner.** For deployments that manage PIN
material externally, you may instead append a `pin-value=<PIN>` or
`pin-source=<file>` attribute to `CUSTOMER_KEY_PKCS11_NAME`. A PIN carried in the
URI takes precedence; with no stored PIN, the in-process callback is a no-op and
the provider uses whatever the URI or token provides.

> **Scope of protection.** Device-wrapping defends *encryption at rest* only. It
> does not defend against a live root compromise of the running provisioner —
> root can re-derive the wrapping key or read the PIN out of process memory. The
> PKCS#11 module, its HSM, and any PIN should be treated as key material and
> protected according to your threat model.

---

## Validating a setup (SoftHSM2 smoke test)

Before provisioning real devices, confirm the whole chain end to end. SoftHSM2
is a pure-software PKCS#11 token that behaves like a real one and is perfect for
this. Run these on the provisioning Raspberry Pi.

> This creates a throwaway token and key for testing. Do not use the test key to
> sign production images.

```sh
# 1. Install SoftHSM2 (test only)
sudo apt-get install -y softhsm2

#    Find the module path (varies by distro/arch); use it below in place of
#    /usr/lib/softhsm/libsofthsm2.so if different:
dpkg -L softhsm2 | grep libsofthsm2.so

# 2. Initialise a token with a user PIN
softhsm2-util --init-token --slot 0 --label testtoken \
    --so-pin 3737 --pin 1234

# 3. Generate an RSA-2048 key ON the token (never leaves it)
#    (pkcs11-tool comes from the opensc package)
sudo apt-get install -y opensc
pkcs11-tool --module /usr/lib/softhsm/libsofthsm2.so \
    --login --pin 1234 \
    --keypairgen --key-type rsa:2048 \
    --label signkey --id 01

# 4. Register the module with p11-kit so the provisioner can see it
echo 'module: /usr/lib/softhsm/libsofthsm2.so' | \
    sudo tee /usr/share/p11-kit/modules/softhsm2.module

# 5. Confirm discovery and find the object alias
p11tool --list-tokens
p11tool --login --list-all 'pkcs11:token=testtoken'
```

Then confirm signing works through the exact provider stack the provisioner
uses. This mirrors what `rpi-sb-keyhelper` does internally:

```sh
# A test payload to sign
echo "rpi-sb-provisioner hsm smoke test" > /tmp/hsm-test.bin

# Public-key export must succeed (this is the step that fails on a
# login-required token if the PIN is wrong or absent)
OPENSSL_CONF=/dev/null openssl pkey -provider pkcs11 -provider default \
    -in 'pkcs11:token=testtoken;object=signkey;type=private;pin-value=1234' \
    -pubout

# Signing must produce an RSA-2048 (256-byte) signature
OPENSSL_CONF=/dev/null openssl dgst -sha256 -provider pkcs11 -provider default \
    -sign 'pkcs11:token=testtoken;object=signkey;type=private;pin-value=1234' \
    /tmp/hsm-test.bin | wc -c   # expect 256
```

If both commands succeed, set in `/etc/rpi-sb-provisioner/config`:

```
CUSTOMER_KEY_PKCS11_NAME='pkcs11:token=testtoken;object=signkey;type=private'
```

store the PIN through the WebUI (**Save PIN & Validate**), and the WebUI should
report the key as **valid for secure boot**. You can then provision a test
device (the `naked` provisioning style is a safe way to exercise signing without
writing an OS image).

---

## Troubleshooting

Errors appear in the provisioning logs and, for validation, in the WebUI. Common
messages and their causes:

| Message | Likely cause | What to check |
| --- | --- | --- |
| `PKCS#11 provider not installed` / provider not available | `pkcs11-provider` package missing | `dpkg -l pkcs11-provider`; reinstall the provisioner's dependencies. |
| `Cannot access PKCS#11 key` (during bootstrap) | Token not visible, wrong URI, or login failed | `p11tool --list-tokens` sees the token? Does the `object=` alias match `p11tool --login --list-all`? Is the PIN stored/correct? |
| `Invalid PIN` / `PIN incorrect or not provided` | Wrong PIN, or none supplied to a login-required token | Re-enter the PIN in the WebUI; confirm the token's user PIN, not the SO PIN. |
| `Key not found on HSM` | The `object=` label does not exist on the token | Compare the alias against `p11tool --login --list-all 'pkcs11:token=<label>'`. |
| `Cannot access HSM - check connection` | Token/slot not present or module can't reach the device | Is the HSM connected/authenticated? Is the module path in the `.module` file correct? |
| Key reported *not fit for purpose* | Key is not RSA-2048 | Generate/import an RSA-2048 key; EC and other RSA sizes are unsupported for Pi secure boot. |
| `type=private` disappears from the URI | Legacy unquoted config truncated at the first `;` | Re-save the value through the WebUI (it now quotes automatically), or manually single-quote it in the config. |

General checks:

- The URI must be **single-quoted** in the config and **percent-encoded**
  (`SIGN key` → `SIGN%20key`).
- `p11tool --login --list-all` is the ground truth for what the token exposes;
  the provisioner sees exactly what p11-kit sees.
- The provisioner ignores `openssl.cnf` for token discovery — register the
  module with **p11-kit**.

---

## See also

- [Configuration Reference — `CUSTOMER_KEY_PKCS11_NAME`](config_vars.md#customer_key_pkcs11_name)
- [Architecture — Signing Helpers](architecture.md#signing-helpers)
- [RFC 7512 — The PKCS #11 URI Scheme](https://www.rfc-editor.org/rfc/rfc7512)
- [OpenSSL pkcs11-provider](https://github.com/latchset/pkcs11-provider)
- [p11-kit](https://p11-glue.github.io/p11-glue/)
