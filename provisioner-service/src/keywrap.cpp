#include "keywrap.h"

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

#include <cstdint>
#include <cstddef>
#include <cstring>
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

    // Locate the DEVICE-flagged OTP key id via the firmware crypto library.
    // Cached across calls: -2 = not yet probed, -1 = none found, >=0 = id.
    // get_num_otp_keys does not bound the key-id space directly, so probe a
    // small fixed range and take the first key flagged as the device key.
    int deviceKeyId() {
        static int cached = -2;
        if (cached != -2) return cached;
        cached = -1;
        for (uint32_t id = 0; id < 16; ++id) {
            uint32_t status = 0;
            if (rpi_fw_crypto_get_key_status(id, &status) != 0) continue;
            if (status & ARM_CRYPTO_KEY_STATUS_TYPE_DEVICE_PRIVATE_KEY) {
                cached = static_cast<int>(id);
                break;
            }
        }
        return cached;
    }

    // wrapping key = HMAC-SHA256(device OTP key, salt), computed inside the
    // firmware via librpifwcrypto. The OTP key never leaves the firmware; only
    // the 32-byte HMAC result is returned to us.
    bool deriveWrapKey(const unsigned char* salt, size_t saltLen, unsigned char outKey[KEY_LEN]) {
        int id = deviceKeyId();
        if (id < 0) return false;
        if (saltLen > RPI_FW_CRYPTO_HMAC_MSG_MAX_SIZE) return false;
        return rpi_fw_crypto_hmac_sha256(0, static_cast<uint32_t>(id),
                                         salt, saltLen, outKey) == 0;
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

bool available() {
    return deviceKeyId() >= 0;
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
