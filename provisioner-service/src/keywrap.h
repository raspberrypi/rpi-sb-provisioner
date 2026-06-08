#pragma once

#include <string>

namespace provisioner {
    namespace keywrap {

        // Device-bound secret wrapping for data at rest.
        //
        // Secrets (the PKCS#11 PIN, uploaded PEM signing keys) are sealed with
        // an AES-256-GCM key derived on-device from the Raspberry Pi firmware
        // crypto service: HMAC-SHA256 over a per-blob random salt using the
        // device-unique OTP key (rpi-fw-crypto). The wrapping key never exists
        // off this board, so a stolen disk image or backup yields only
        // ciphertext.
        //
        // SCOPE: encryption at rest only. This does NOT defend against a live
        // root compromise of the running host - root can re-derive the key via
        // rpi-fw-crypto or read the plaintext out of process memory.
        //
        // This translation unit is deliberately free of any drogon / web-server
        // dependency so it can be linked into both the provisioner service and
        // the standalone signing helper (rpi-sb-keyhelper). It does not log;
        // callers decide how to report failures.

        // True if device-bound wrapping is usable on this host: rpi-fw-crypto is
        // present and a DEVICE-flagged OTP key was found. Result is cached.
        bool available();

        // Wrap plaintext into a versioned blob. Returns false on any failure
        // (no usable device key, RNG failure, cipher failure).
        bool wrap(const std::string& plaintext, std::string& wrappedOut);

        // Unwrap a blob produced by wrap(). Returns false if the blob is not
        // wrapped, is truncated/corrupt, or authentication fails (wrong device).
        bool unwrap(const std::string& wrapped, std::string& plaintextOut);

        // True if blob carries the wrap magic (i.e. is wrapped, not legacy
        // plaintext). Cheap header check; does not touch the device.
        bool isWrapped(const std::string& blob);

    } // namespace keywrap
} // namespace provisioner
