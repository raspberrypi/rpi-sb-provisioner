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

        // How the firmware crypto service answers when asked for a wrapping key.
        // Ordered from "nothing to be done here" to "usable", so callers can
        // test for Ok as the single state in which wrapping can succeed.
        //
        // The distinction that matters operationally is Blank vs the rest: a
        // blank slot is the one failure an operator can fix on the spot, by
        // generating a key. Everything else is a property of the host.
        // Ordered by how close the host is to being usable, so that when
        // several slots fail differently the most informative - and most
        // actionable - answer is the one reported.
        enum class DeviceKeyState {
            NoService,   // service unreachable: build chroot, non-Pi, no /dev/vcio
            NoSlot,      // service reachable, but the SoC exposes no usable key slot
            Locked,      // slot present and unprogrammed, and generation is locked out
            Blank,       // slot present and unprogrammed - generation would fix it
            Ok,          // a key is present and an HMAC over it succeeds
        };

        struct DeviceKeyStatus {
            DeviceKeyState state = DeviceKeyState::NoService;
            int keyId = -1;             // the slot examined, -1 if none was found
            bool deviceUnique = false;  // slot carries the DEVICE flag
            std::string reason;         // what is wrong, in UI-presentable prose
            std::string remedy;         // what would fix it; empty when nothing can
        };

        // Stable lowercase name for a state, for JSON payloads and logs.
        const char* stateName(DeviceKeyState state);

        // Classify this host's wrapping key.
        //
        // The probe ends in an actual HMAC, not a public key read, because that
        // is the operation wrap() performs and the two do not always agree: a
        // slot can report a status yet hold all zeros, which is exactly how a
        // never-programmed device key presents.
        //
        // A usable key is cached for the life of the process; a failure is
        // cached only briefly, so a host that becomes usable - the firmware
        // service arriving late, or something else programming the slot - is
        // picked up without a service restart. provisionDeviceKey() invalidates
        // the cache outright.
        DeviceKeyStatus deviceKeyStatus();


        // Generate a key in the blank slot found by deviceKeyStatus().
        //
        // THIS BURNS OTP AND CANNOT BE UNDONE. The slot on a BCM2712 is the
        // device-unique key slot - there is no scratch slot to prefer - so this
        // must only ever run on explicit operator consent, never as a silent
        // repair on a write path. Refuses unless the state is Blank.
        //
        // On success the cache is invalidated and outStatus reports the new
        // state; on failure outStatus carries the reason.
        bool provisionDeviceKey(DeviceKeyStatus& outStatus);

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
