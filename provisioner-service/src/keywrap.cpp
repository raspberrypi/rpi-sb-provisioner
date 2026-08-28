#include "keywrap.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <chrono>
#include <cstdint>
#include <cstddef>
#include <cstring>
#include <mutex>
#include <string>
#include <vector>

// Raspberry Pi firmware crypto service. rpifwcrypto.h uses the fixed-width
// integer types without including <cstdint> itself, so it must come after.
#include <rpifwcrypto.h>

namespace provisioner {
namespace keywrap {

namespace {

    // Versioned blob layout: magic || salt || iv || tag || ciphertext.
    // Bumping the format means bumping the magic so old blobs are rejected
    // cleanly rather than misread.
    constexpr char   MAGIC[8]   = {'R', 'P', 'I', 'S', 'B', 'W', '1', '\0'};
    constexpr size_t MAGIC_LEN  = 8;
    constexpr size_t SALT_LEN   = 32;   // HMAC input -> device-bound KDF
    constexpr size_t IV_LEN     = 12;   // AES-GCM nonce
    constexpr size_t TAG_LEN    = 16;   // AES-GCM auth tag
    constexpr size_t KEY_LEN    = 32;   // AES-256
    constexpr size_t HEADER_LEN = MAGIC_LEN + SALT_LEN + IV_LEN + TAG_LEN;

    // HMAC-SHA256 output is exactly 32 bytes, which is also our AES-256 key
    // length - assert the firmware contract matches the buffer we hand it.
    static_assert(KEY_LEN == 32, "HMAC-SHA256 / AES-256 key length must be 32");

    // Probe message for the liveness HMAC. Only whether the firmware will
    // compute over it matters, never the result, but it must stay stable so the
    // probe never puts anything derived from a secret on the wire.
    //
    // A man is not dead while his name is still spoken.
    constexpr char PROBE_MSG[] = "GNU TERRY PRATCHETT";

    // get_num_otp_keys() reports how many keys the SoC has, not which ids are
    // valid, so the id space is probed directly. On BCM2712 exactly one slot
    // exists and it is id 1; the range is kept wider than that in case a future
    // SoC exposes more.
    constexpr uint32_t MAX_KEY_ID = 16;

    std::mutex g_statusMutex;
    bool g_statusCached = false;
    DeviceKeyStatus g_status;
    std::chrono::steady_clock::time_point g_statusAt;

    // How long a failed classification is trusted before the firmware is asked
    // again. A usable key is not re-probed on a timer: it sits on the hot path
    // of every wrap and unwrap. It can still stop answering - HMAC_LOCKED is
    // settable at runtime and persists until reboot - but deriveWrapKey() drops
    // the classification at the moment the firmware refuses, which catches that
    // sooner than any poll would and costs nothing while it does not happen.
    //
    // A failure must not be cached that way, because the conditions behind one
    // are precisely the ones that change under us: the slot being programmed
    // while we run, by rpi-connect registration or genkey from the CLI, or the
    // firmware crypto service not having been reachable when we started.
    // Without this, a station that answered "no" once keeps saying so until it
    // is restarted, including through the status endpoint the Options page
    // banner reads.
    constexpr std::chrono::seconds NEGATIVE_STATUS_TTL{5};

    // Drop the cached classification so the next caller re-probes. Callers must
    // not hold g_statusMutex.
    void invalidateStatus() {
        std::lock_guard<std::mutex> lock(g_statusMutex);
        g_statusCached = false;
    }

    // Classify one slot by asking the firmware to HMAC with it. Returns true
    // only when the slot is genuinely usable for wrapping.
    //
    // A key that has never been programmed reads back as all zeros and the
    // firmware reports KEY_NOT_SET rather than KEY_NOT_FOUND, which is the
    // difference between "this host has no such slot" and "this host has the
    // slot but nobody ever put a key in it" - the second being the one an
    // operator can fix.
    bool probeSlot(uint32_t id, DeviceKeyStatus& out) {
        uint32_t slotStatus = 0;
        if (rpi_fw_crypto_get_key_status(id, &slotStatus) != 0) {
            return false; // no such slot on this SoC
        }

        out.keyId = static_cast<int>(id);
        out.deviceUnique = (slotStatus & ARM_CRYPTO_KEY_STATUS_TYPE_DEVICE_PRIVATE_KEY) != 0;

        unsigned char digest[KEY_LEN];
        if (rpi_fw_crypto_hmac_sha256(0, id,
                                      reinterpret_cast<const uint8_t*>(PROBE_MSG),
                                      sizeof(PROBE_MSG) - 1, digest) == 0) {
            OPENSSL_cleanse(digest, sizeof(digest));
            out.state = DeviceKeyState::Ok;
            return true;
        }

        switch (rpi_fw_crypto_get_last_error()) {
        case RPI_FW_CRYPTO_KEY_NOT_SET:
            // The slot exists but holds all zeros. Generation is gated by
            // GEN_LOCKED specifically - READ_LOCKED, which config.txt's
            // lock_device_private_key=1 sets on every boot, does not prevent it.
            if (slotStatus & ARM_CRYPTO_KEY_STATUS_GEN_LOCKED) {
                out.state = DeviceKeyState::Locked;
                out.reason = "This host's OTP key slot has never been programmed, "
                             "and key generation is locked out.";
                out.remedy = "Key generation is locked until the next reboot. Reboot "
                             "and try again; if it persists, the slot cannot be "
                             "programmed on this host.";
            } else {
                out.state = DeviceKeyState::Blank;
                out.reason = "This host's OTP key slot has never been programmed, so "
                             "there is no device key to protect stored secrets with.";
                out.remedy = "Generate a device key for this host. This writes to OTP "
                             "and cannot be undone.";
            }
            return false;

        case RPI_FW_CRYPTO_KEY_LOCKED:
            out.state = DeviceKeyState::Locked;
            out.reason = "This host's OTP key slot has HMAC operations locked out.";
            out.remedy = "The lock persists until the next reboot. Reboot and try again.";
            return false;

        default:
            // The slot answered get_key_status but will not HMAC for a reason
            // that is not a lock or a blank key. Report it verbatim rather than
            // guessing, and keep looking in case another slot serves.
            out.state = DeviceKeyState::NoSlot;
            out.reason = std::string("This host's OTP key slot is unusable: ")
                       + rpi_fw_crypto_strerror(rpi_fw_crypto_get_last_error()) + ".";
            out.remedy.clear();
            return false;
        }
    }

    DeviceKeyStatus probeDeviceKey() {
        DeviceKeyStatus status;

        if (rpi_fw_crypto_get_num_otp_keys() < 0) {
            status.state = DeviceKeyState::NoService;
            status.reason = "The Raspberry Pi firmware crypto service is not available "
                            "on this host, so secrets cannot be encrypted at rest.";
            status.remedy = "This is expected in a build chroot or on non-Pi hardware. "
                            "On a provisioning station, check that /dev/vcio_crypto exists and "
                            "the firmware is up to date.";
            return status;
        }

        // First usable slot wins. A slot that is merely blank is remembered as
        // the best answer so far, so the reported reason describes a fixable
        // host rather than whichever id happened to be probed last.
        DeviceKeyStatus best;
        best.state = DeviceKeyState::NoSlot;
        best.reason = "This host exposes no OTP key slot, so secrets cannot be "
                      "encrypted at rest.";

        for (uint32_t id = 0; id < MAX_KEY_ID; ++id) {
            DeviceKeyStatus probe;
            if (probeSlot(id, probe)) {
                return probe;
            }
            if (probe.state > best.state) {
                best = probe;
            }
        }
        return best;
    }

    // The slot wrap()/unwrap() derive from, or -1 when there is none.
    int wrappingKeyId() {
        const DeviceKeyStatus status = deviceKeyStatus();
        return status.state == DeviceKeyState::Ok ? status.keyId : -1;
    }

    // wrapping key = HMAC-SHA256(OTP key, salt), computed inside the firmware
    // via librpifwcrypto. The OTP key never leaves the firmware; only the
    // 32-byte HMAC result is returned to us.
    bool deriveWrapKey(const unsigned char* salt, size_t saltLen, unsigned char outKey[KEY_LEN]) {
        int id = wrappingKeyId();
        if (id < 0) return false;
        if (saltLen > RPI_FW_CRYPTO_HMAC_MSG_MAX_SIZE) return false;
        if (rpi_fw_crypto_hmac_sha256(0, static_cast<uint32_t>(id),
                                      salt, saltLen, outKey) == 0) {
            return true;
        }

        // The classification promised this slot would HMAC and it has just
        // refused, so the cached answer is now wrong in the one direction the
        // TTL does not cover. Drop it, so the caller that reports this failure
        // to the operator - and the banner they look at next - describe the
        // host as it is rather than repeating the answer that just failed.
        invalidateStatus();
        return false;
    }

    bool gcmEncrypt(const unsigned char key[KEY_LEN], const unsigned char iv[IV_LEN],
                    const std::string& pt, std::string& ct, unsigned char tag[TAG_LEN]) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        bool ok = false;
        std::vector<unsigned char> buf(pt.size());
        int len = 0, total = 0;
        do {
            if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) break;
            if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) break;
            if (!pt.empty()) {
                if (EVP_EncryptUpdate(ctx, buf.data(), &len,
                                      reinterpret_cast<const unsigned char*>(pt.data()),
                                      static_cast<int>(pt.size())) != 1) break;
                total = len;
            }
            if (EVP_EncryptFinal_ex(ctx, buf.data() + total, &len) != 1) break;
            total += len;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) break;
            ct.assign(reinterpret_cast<const char*>(buf.data()), static_cast<size_t>(total));
            ok = true;
        } while (false);
        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

    bool gcmDecrypt(const unsigned char key[KEY_LEN], const unsigned char iv[IV_LEN],
                    const std::string& ct, const unsigned char tag[TAG_LEN], std::string& pt) {
        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) return false;
        bool ok = false;
        std::vector<unsigned char> buf(ct.size());
        int len = 0, total = 0;
        do {
            if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) break;
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, IV_LEN, nullptr) != 1) break;
            if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key, iv) != 1) break;
            if (!ct.empty()) {
                if (EVP_DecryptUpdate(ctx, buf.data(), &len,
                                      reinterpret_cast<const unsigned char*>(ct.data()),
                                      static_cast<int>(ct.size())) != 1) break;
                total = len;
            }
            if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LEN,
                                    const_cast<unsigned char*>(tag)) != 1) break;
            // Final fails if the tag does not authenticate (wrong device key,
            // tampered ciphertext): treated as an unwrap failure.
            if (EVP_DecryptFinal_ex(ctx, buf.data() + total, &len) != 1) break;
            total += len;
            pt.assign(reinterpret_cast<const char*>(buf.data()), static_cast<size_t>(total));
            ok = true;
        } while (false);
        if (!buf.empty()) OPENSSL_cleanse(buf.data(), buf.size());
        EVP_CIPHER_CTX_free(ctx);
        return ok;
    }

} // namespace

bool isWrapped(const std::string& blob) {
    return blob.size() >= MAGIC_LEN && std::memcmp(blob.data(), MAGIC, MAGIC_LEN) == 0;
}

const char* stateName(DeviceKeyState state) {
    switch (state) {
    case DeviceKeyState::NoService: return "no_service";
    case DeviceKeyState::NoSlot:    return "no_slot";
    case DeviceKeyState::Locked:    return "locked";
    case DeviceKeyState::Blank:     return "blank";
    case DeviceKeyState::Ok:        return "ok";
    }
    return "unknown";
}

DeviceKeyStatus deviceKeyStatus() {
    std::lock_guard<std::mutex> lock(g_statusMutex);
    const bool fresh = g_statusCached
                       && (g_status.state == DeviceKeyState::Ok
                           || std::chrono::steady_clock::now() - g_statusAt < NEGATIVE_STATUS_TTL);
    if (!fresh) {
        g_status = probeDeviceKey();
        // Stamped after the probe, so the TTL measures from when the answer was
        // obtained rather than from when it was asked for.
        g_statusAt = std::chrono::steady_clock::now();
        g_statusCached = true;
    }
    return g_status;
}


bool provisionDeviceKey(DeviceKeyStatus& outStatus) {
    outStatus = deviceKeyStatus();

    // Only a blank slot may be written. Every other state either needs no key
    // (Ok) or would not be helped by one, and gen_ecdsa_key on a populated slot
    // is refused by the firmware anyway - but refusing here keeps the
    // irreversible call off any path that did not deliberately ask for it.
    if (outStatus.state != DeviceKeyState::Blank || outStatus.keyId < 0) {
        return false;
    }

    if (rpi_fw_crypto_gen_ecdsa_key(0, static_cast<uint32_t>(outStatus.keyId)) != 0) {
        outStatus.reason = std::string("Generating a device key failed: ")
                         + rpi_fw_crypto_strerror(rpi_fw_crypto_get_last_error()) + ".";
        outStatus.remedy.clear();
        return false;
    }

    // Re-probe rather than assume success wrote something usable: the point of
    // the HMAC probe is that a slot's status and its contents can disagree.
    invalidateStatus();
    outStatus = deviceKeyStatus();
    return outStatus.state == DeviceKeyState::Ok;
}

bool wrap(const std::string& plaintext, std::string& wrappedOut) {
    unsigned char salt[SALT_LEN], iv[IV_LEN], key[KEY_LEN], tag[TAG_LEN];
    if (RAND_bytes(salt, SALT_LEN) != 1 || RAND_bytes(iv, IV_LEN) != 1) return false;
    if (!deriveWrapKey(salt, SALT_LEN, key)) return false;

    std::string ct;
    bool ok = gcmEncrypt(key, iv, plaintext, ct, tag);
    OPENSSL_cleanse(key, KEY_LEN);
    if (!ok) return false;

    wrappedOut.clear();
    wrappedOut.reserve(HEADER_LEN + ct.size());
    wrappedOut.append(MAGIC, MAGIC_LEN);
    wrappedOut.append(reinterpret_cast<const char*>(salt), SALT_LEN);
    wrappedOut.append(reinterpret_cast<const char*>(iv), IV_LEN);
    wrappedOut.append(reinterpret_cast<const char*>(tag), TAG_LEN);
    wrappedOut.append(ct);
    return true;
}

bool unwrap(const std::string& wrapped, std::string& plaintextOut) {
    if (!isWrapped(wrapped) || wrapped.size() < HEADER_LEN) return false;
    const unsigned char* p = reinterpret_cast<const unsigned char*>(wrapped.data());
    const unsigned char* salt = p + MAGIC_LEN;
    const unsigned char* iv   = p + MAGIC_LEN + SALT_LEN;
    const unsigned char* tag  = p + MAGIC_LEN + SALT_LEN + IV_LEN;
    std::string ct = wrapped.substr(HEADER_LEN);

    unsigned char key[KEY_LEN];
    if (!deriveWrapKey(salt, SALT_LEN, key)) return false;
    bool ok = gcmDecrypt(key, iv, ct, tag, plaintextOut);
    OPENSSL_cleanse(key, KEY_LEN);
    return ok;
}

} // namespace keywrap
} // namespace provisioner
