#include "pkcs11_common.h"

#include "keywrap.h"

#include <openssl/crypto.h>

#include <algorithm>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace provisioner {
    namespace pkcs11 {

        std::string readStoredPin(PinStatus* status) {
            auto set = [status](PinStatus s) { if (status) *status = s; };

            if (!std::filesystem::exists(PIN_FILE)) {
                set(PinStatus::NotConfigured);
                return {};
            }
            std::ifstream pinFile(PIN_FILE, std::ios::binary);
            if (!pinFile.is_open()) {
                set(PinStatus::ReadError);
                return {};
            }
            std::string raw((std::istreambuf_iterator<char>(pinFile)),
                            std::istreambuf_iterator<char>());

            // PINs are stored device-wrapped at rest (see savePkcs11Pin). A blob
            // without the wrap magic is a legacy plaintext PIN from before
            // wrapping existed: read it as-is so the install keeps working; it is
            // re-wrapped the next time the PIN is saved.
            std::string pin;
            if (keywrap::isWrapped(raw)) {
                if (!keywrap::unwrap(raw, pin)) {
                    set(PinStatus::UnwrapFailed);
                    return {};
                }
                set(PinStatus::Ok);
            } else {
                pin = raw;
                set(PinStatus::LegacyPlaintext);
            }

            // The PIN is stored without a trailing newline, but strip any stray
            // trailing whitespace defensively.
            while (!pin.empty() && (pin.back() == '\n' || pin.back() == '\r')) {
                pin.pop_back();
            }
            return pin;
        }

        int pinPasswordCallback(char* buf, int size, int /*rwflag*/, void* u) {
            const auto* pin = static_cast<const std::string*>(u);
            if (!pin || pin->empty() || size <= 0) {
                return 0;
            }
            int len = static_cast<int>(std::min(pin->size(), static_cast<size_t>(size)));
            std::memcpy(buf, pin->data(), static_cast<size_t>(len));
            return len;
        }

        bool Context::load() {
            libctx = OSSL_LIB_CTX_new();
            if (!libctx) {
                return false;
            }
            defProv = OSSL_PROVIDER_load(libctx, "default");
            p11Prov = OSSL_PROVIDER_load(libctx, "pkcs11");
            return p11Prov != nullptr;
        }

        Context::~Context() {
            // Providers must be unloaded before the context is freed; any
            // EVP_PKEY obtained from the context must already have been freed by
            // the caller before this runs.
            if (p11Prov) {
                OSSL_PROVIDER_unload(p11Prov);
            }
            if (defProv) {
                OSSL_PROVIDER_unload(defProv);
            }
            if (libctx) {
                OSSL_LIB_CTX_free(libctx);
            }
        }

    } // namespace pkcs11
} // namespace provisioner
