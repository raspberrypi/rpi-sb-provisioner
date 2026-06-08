// Standalone signing helper for device-wrapped customer keys.
//
// Mirrors rpi-sb-pkcs11-sign.sh's contract for the Raspberry Pi signing tools:
// given a file to sign, emit a PKCS#1 v1.5 RSA SHA-256 signature as lowercase
// hex on stdout. The customer private key is stored wrapped at rest (see
// keywrap); this tool unwraps it in its own process memory, signs, and never
// writes the plaintext key to disk or hands it back to the calling shell.
//
// Usage:
//   rpi-sb-keyhelper sign   --key <wrapped-key-file> --in <file-to-sign>
//   rpi-sb-keyhelper pubkey --key <wrapped-key-file>
//
// A wrapped key is unwrapped first; a legacy plaintext key is used as-is, so a
// freshly migrated install keeps working before the key is re-uploaded.
//
// Deliberately free of drogon: links only OpenSSL + keywrap.

#include "keywrap.h"

#include <openssl/bio.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <cstdio>
#include <cstring>
#include <fstream>
#include <iterator>
#include <string>
#include <vector>

namespace {

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
    std::vector<unsigned char> sig;
    size_t siglen = 0;
    do {
        if (!mdctx) break;
        if (EVP_DigestSignInit(mdctx, nullptr, EVP_sha256(), nullptr, pkey) != 1) break;
        if (EVP_DigestSign(mdctx, nullptr, &siglen,
                           reinterpret_cast<const unsigned char*>(data.data()),
                           data.size()) != 1) break;
        sig.resize(siglen);
        if (EVP_DigestSign(mdctx, sig.data(), &siglen,
                           reinterpret_cast<const unsigned char*>(data.data()),
                           data.size()) != 1) break;
        sig.resize(siglen);

        // Lowercase hex, no trailing newline - matches the `xxd -p` output the
        // Raspberry Pi signing tools consume from the PKCS#11 wrapper.
        static const char H[] = "0123456789abcdef";
        std::string hex;
        hex.reserve(siglen * 2);
        for (unsigned char b : sig) { hex.push_back(H[b >> 4]); hex.push_back(H[b & 0x0f]); }
        std::fwrite(hex.data(), 1, hex.size(), stdout);
        rc = 0;
    } while (false);

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

const char* argAfter(int argc, char** argv, const char* flag) {
    for (int i = 2; i < argc - 1; ++i)
        if (std::strcmp(argv[i], flag) == 0) return argv[i + 1];
    return nullptr;
}

void usage() {
    std::fprintf(stderr,
                 "Usage:\n"
                 "  rpi-sb-keyhelper sign   --key <wrapped-key-file> --in <file-to-sign>\n"
                 "  rpi-sb-keyhelper pubkey --key <wrapped-key-file>\n");
}

} // namespace

int main(int argc, char** argv) {
    if (argc < 2) { usage(); return 2; }
    const std::string cmd = argv[1];
    const char* key = argAfter(argc, argv, "--key");
    const char* in  = argAfter(argc, argv, "--in");

    if (cmd == "sign") {
        if (!key || !in) { usage(); return 2; }
        return cmdSign(key, in);
    }
    if (cmd == "pubkey") {
        if (!key) { usage(); return 2; }
        return cmdPubkey(key);
    }
    usage();
    return 2;
}
