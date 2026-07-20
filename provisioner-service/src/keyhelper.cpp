// Standalone signing helper for customer keys held out of the calling shell.
//
// Mirrors rpi-sb-pkcs11-sign.sh's contract for the Raspberry Pi signing tools:
// given a file to sign, emit a PKCS#1 v1.5 RSA SHA-256 signature as lowercase
// hex on stdout. Two key sources are supported:
//
//   * A device-wrapped PEM key (--key): stored wrapped at rest (see keywrap);
//     this tool unwraps it in its own process memory, signs, and never writes
//     the plaintext key to disk or hands it back to the calling shell.
//
//   * A PKCS#11 token key (--pkcs11-uri): the private key never leaves the HSM.
//     The token PIN saved through the WebUI is stored device-wrapped at
//     /etc/rpi-sb-provisioner/keys/pkcs11.pin; this tool unwraps it in memory
//     and supplies it to the pkcs11-provider via OpenSSL's passphrase callback,
//     so the PIN never appears on a command line or in a pin-source= file. This
//     is what connects the stored PIN to provisioning-time signing - the shell
//     path has no other way to log in to the token.
//
// Usage:
//   rpi-sb-keyhelper sign   --key <wrapped-key-file> --in <file-to-sign>
//   rpi-sb-keyhelper pubkey --key <wrapped-key-file>
//   rpi-sb-keyhelper sign   --pkcs11-uri <uri> --in <file-to-sign>
//   rpi-sb-keyhelper pubkey --pkcs11-uri <uri>
//
// A wrapped PEM key is unwrapped first; a legacy plaintext key is used as-is,
// so a freshly migrated install keeps working before the key is re-uploaded.
// Likewise a legacy plaintext PIN is honoured until the PIN is re-saved.
//
// Deliberately free of drogon: links only OpenSSL + keywrap.

#include "keywrap.h"
#include "pkcs11_common.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/store.h>
#include <openssl/ui.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

namespace pkcs11 = provisioner::pkcs11;

std::string readFile(const std::string& path, bool& ok) {
    std::ifstream f(path, std::ios::binary);
    if (!f) { ok = false; return {}; }
    std::string data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    ok = true;
    return data;
}

// Load the (possibly wrapped) private key into an EVP_PKEY. The decrypted PEM
// exists only on this process's heap and is cleansed before return.
EVP_PKEY* loadKey(const std::string& keyPath) {
    bool ok = false;
    std::string blob = readFile(keyPath, ok);
    if (!ok) {
        std::fprintf(stderr, "keyhelper: cannot read key file: %s\n", keyPath.c_str());
        return nullptr;
    }

    std::string pem;
    if (provisioner::keywrap::isWrapped(blob)) {
        if (!provisioner::keywrap::unwrap(blob, pem)) {
            std::fprintf(stderr, "keyhelper: failed to unwrap key "
                                 "(wrong device or corrupt blob)\n");
            return nullptr;
        }
    } else {
        pem = blob; // legacy plaintext key
    }

    EVP_PKEY* pkey = nullptr;
    BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
    if (bio) {
        auto noPrompt = [](char*, int, int, void*) -> int { return 0; };
        pkey = PEM_read_bio_PrivateKey(bio, nullptr, noPrompt, nullptr);
        BIO_free(bio);
    }
    if (!pem.empty()) OPENSSL_cleanse(&pem[0], pem.size());
    if (!pkey) std::fprintf(stderr, "keyhelper: failed to parse private key\n");
    return pkey;
}

// Read and unwrap the stored PKCS#11 PIN via the shared primitive, adding this
// tool's stderr diagnostics (pkcs11_common is deliberately logger-free).
// Returns empty if no PIN is configured or it cannot be unwrapped; signing then
// falls back to whatever the URI or token provide (a token with no login
// requirement, or a pin-value=/pin-source= carried in the URI).
std::string readPinLogged() {
    pkcs11::PinStatus status = pkcs11::PinStatus::NotConfigured;
    std::string pin = pkcs11::readStoredPin(&status);
    if (status == pkcs11::PinStatus::UnwrapFailed) {
        std::fprintf(stderr, "keyhelper: failed to unwrap stored PKCS#11 PIN "
                             "(wrong device or corrupt file)\n");
    }
    return pin;
}

// Run the two-pass EVP_DigestSign on an already-initialised context and print
// the signature as lowercase hex with no trailing newline - matching the
// `xxd -p` output the Raspberry Pi signing tools consume from the wrappers.
// Returns 0 on success, 1 on failure.
int emitSignatureHex(EVP_MD_CTX* mdctx, const std::string& data) {
    size_t siglen = 0;
    if (EVP_DigestSign(mdctx, nullptr, &siglen,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.size()) != 1) {
        return 1;
    }
    std::vector<unsigned char> sig(siglen);
    if (EVP_DigestSign(mdctx, sig.data(), &siglen,
                       reinterpret_cast<const unsigned char*>(data.data()),
                       data.size()) != 1) {
        return 1;
    }
    sig.resize(siglen);

    static const char H[] = "0123456789abcdef";
    std::string hex;
    hex.reserve(siglen * 2);
    for (unsigned char b : sig) { hex.push_back(H[b >> 4]); hex.push_back(H[b & 0x0f]); }
    std::fwrite(hex.data(), 1, hex.size(), stdout);
    return 0;
}

int cmdSign(const std::string& keyPath, const std::string& inPath) {
    bool ok = false;
    std::string data = readFile(inPath, ok);
    if (!ok) {
        std::fprintf(stderr, "keyhelper: cannot read input file: %s\n", inPath.c_str());
        return 1;
    }

    EVP_PKEY* pkey = loadKey(keyPath);
    if (!pkey) return 1;

    int rc = 1;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx && EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) == 1) {
        rc = emitSignatureHex(mdctx, data);
    }

    if (mdctx) EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    if (rc != 0) std::fprintf(stderr, "keyhelper: signing failed\n");
    return rc;
}

int cmdPubkey(const std::string& keyPath) {
    EVP_PKEY* pkey = loadKey(keyPath);
    if (!pkey) return 1;
    int rc = 1;
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out && PEM_write_bio_PUBKEY(out, pkey) == 1) rc = 0;
    if (out) BIO_free(out);
    EVP_PKEY_free(pkey);
    if (rc != 0) std::fprintf(stderr, "keyhelper: public-key export failed\n");
    return rc;
}

// ===== PKCS#11 (HSM) support =====

// Load the private key identified by a pkcs11: URI, supplying the stored PIN
// in-process via the passphrase callback so the token's C_Login succeeds
// without the PIN ever reaching a command line or a pin-source= file. The
// returned EVP_PKEY is bound to ctx.libctx and must be freed before ctx is
// destroyed. Mirrors the OSSL_STORE load in utils.cpp::parsePkcs11Key.
EVP_PKEY* loadPkcs11Key(pkcs11::Context& ctx, const std::string& uri, std::string& pin) {
    UI_METHOD* uiMethod = UI_UTIL_wrap_read_pem_callback(pkcs11::pinPasswordCallback, 0);
    if (!uiMethod) {
        return nullptr;
    }

    ERR_clear_error();

    EVP_PKEY* pkey = nullptr;
    OSSL_STORE_CTX* sctx = OSSL_STORE_open_ex(uri.c_str(), ctx.libctx, nullptr,
                                              uiMethod, &pin, nullptr, nullptr, nullptr);
    if (sctx) {
        // Bias the store toward a key object so it does not pull in certificates
        // or other associated objects.
        OSSL_STORE_expect(sctx, OSSL_STORE_INFO_PKEY);
        while (pkey == nullptr && OSSL_STORE_eof(sctx) != 1) {
            OSSL_STORE_INFO* si = OSSL_STORE_load(sctx);
            if (!si) {
                if (OSSL_STORE_error(sctx) == 1) {
                    break;
                }
                continue;
            }
            if (OSSL_STORE_INFO_get_type(si) == OSSL_STORE_INFO_PKEY) {
                pkey = OSSL_STORE_INFO_get1_PKEY(si);
            }
            OSSL_STORE_INFO_free(si);
        }
        OSSL_STORE_close(sctx);
    }

    UI_destroy_method(uiMethod);
    return pkey;
}

int cmdSignPkcs11(const std::string& uri, const std::string& inPath) {
    bool ok = false;
    std::string data = readFile(inPath, ok);
    if (!ok) {
        std::fprintf(stderr, "keyhelper: cannot read input file: %s\n", inPath.c_str());
        return 1;
    }

    pkcs11::Context ctx;
    if (!ctx.load()) {
        std::fprintf(stderr, "keyhelper: PKCS#11 provider not available\n");
        return 1;
    }

    std::string pin = readPinLogged();
    EVP_PKEY* pkey = loadPkcs11Key(ctx, uri, pin);
    if (!pin.empty()) OPENSSL_cleanse(&pin[0], pin.size());
    if (!pkey) {
        std::fprintf(stderr, "keyhelper: cannot access PKCS#11 key "
                             "(token present? PIN correct? URI valid?)\n");
        return 1;
    }

    // The digest (SHA-256) is fetched from ctx.libctx (default provider) while
    // the RSA signature dispatches to the pkcs11-provider via pkey - i.e. the
    // hash is computed in software and the raw sign happens on the token, the
    // same operation `openssl dgst -sha256 -sign pkcs11:...` performed before.
    int rc = 1;
    EVP_MD_CTX* mdctx = EVP_MD_CTX_new();
    if (mdctx && EVP_DigestSignInit_ex(mdctx, nullptr, "SHA256", ctx.libctx,
                                       nullptr, pkey, nullptr) == 1) {
        rc = emitSignatureHex(mdctx, data);
    }

    if (mdctx) EVP_MD_CTX_free(mdctx);
    EVP_PKEY_free(pkey);
    if (rc != 0) std::fprintf(stderr, "keyhelper: PKCS#11 signing failed\n");
    return rc;
}

int cmdPubkeyPkcs11(const std::string& uri) {
    pkcs11::Context ctx;
    if (!ctx.load()) {
        std::fprintf(stderr, "keyhelper: PKCS#11 provider not available\n");
        return 1;
    }

    std::string pin = readPinLogged();
    EVP_PKEY* pkey = loadPkcs11Key(ctx, uri, pin);
    if (!pin.empty()) OPENSSL_cleanse(&pin[0], pin.size());
    if (!pkey) {
        std::fprintf(stderr, "keyhelper: cannot access PKCS#11 key "
                             "(token present? PIN correct? URI valid?)\n");
        return 1;
    }

    int rc = 1;
    BIO* out = BIO_new_fp(stdout, BIO_NOCLOSE);
    if (out && PEM_write_bio_PUBKEY(out, pkey) == 1) rc = 0;
    if (out) BIO_free(out);
    EVP_PKEY_free(pkey);
    if (rc != 0) std::fprintf(stderr, "keyhelper: PKCS#11 public-key export failed\n");
    return rc;
}

const char* argAfter(int argc, char** argv, const char* flag) {
    for (int i = 2; i < argc - 1; ++i)
        if (std::strcmp(argv[i], flag) == 0) return argv[i + 1];
    return nullptr;
}

void usage() {
    std::fprintf(stderr,
                 "Usage:\n"
                 "  rpi-sb-keyhelper sign   --key <wrapped-key-file> --in <file-to-sign>\n"
                 "  rpi-sb-keyhelper pubkey --key <wrapped-key-file>\n"
                 "  rpi-sb-keyhelper sign   --pkcs11-uri <uri> --in <file-to-sign>\n"
                 "  rpi-sb-keyhelper pubkey --pkcs11-uri <uri>\n");
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    const std::string cmd = argv[1];
    const char* key = argAfter(argc, argv, "--key");
    const char* in  = argAfter(argc, argv, "--in");
    const char* p11 = argAfter(argc, argv, "--pkcs11-uri");

    if (cmd == "sign") {
        if (p11 && in) return cmdSignPkcs11(p11, in);
        if (key && in) return cmdSign(key, in);
        usage();
        return 2;
    }
    if (cmd == "pubkey") {
        if (p11) return cmdPubkeyPkcs11(p11);
        if (key) return cmdPubkey(key);
        usage();
        return 2;
    }
    usage();
    return 2;
}
