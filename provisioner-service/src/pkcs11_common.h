#pragma once

#include <string>

#include <openssl/provider.h>
#include <openssl/types.h>

// Shared PKCS#11 provider-load and PIN-unwrap primitives.
//
// Both the provisioner service (utils.cpp) and the standalone signing helper
// (rpi-sb-keyhelper) need to load the OpenSSL pkcs11-provider into a private
// library context and hand the device-wrapped token PIN to it in-process. This
// is the single home for that logic so the two never drift apart.
//
// Like keywrap, this translation unit is deliberately free of any drogon /
// web-server dependency (so it can link into the lean keyhelper) and it does
// NOT log: callers report failures with whatever logger is appropriate, driven
// by the returned status.

namespace provisioner {
    namespace pkcs11 {

        // Path to the device-wrapped PKCS#11 token PIN stored by the WebUI.
        // Single source of truth (utils.h aliases this as PKCS11_PIN_FILE).
        constexpr const char* PIN_FILE = "/etc/rpi-sb-provisioner/keys/pkcs11.pin";

        // Outcome of readStoredPin(), so a caller can log/scrub appropriately
        // without this TU pulling in a logger.
        enum class PinStatus {
            Ok,              // wrapped PIN read and unwrapped successfully
            NotConfigured,   // no PIN file present
            ReadError,       // file present but could not be opened
            UnwrapFailed,    // wrapped but unwrap failed (wrong device / corrupt)
            LegacyPlaintext, // present but not wrapped; returned as-is
        };

        // Read and unwrap the stored PIN. Returns the PIN (empty on any failure
        // or when none is configured); *status, if given, distinguishes the
        // cases. The returned string holds plaintext PIN material - the caller
        // should OPENSSL_cleanse it after use.
        std::string readStoredPin(PinStatus* status = nullptr);

        // pem_password_cb that copies a PIN held in *u into OpenSSL's buffer.
        // Wrap it in a UI_METHOD via UI_UTIL_wrap_read_pem_callback so
        // OSSL_STORE's passphrase prompts (the pkcs11-provider's C_Login) are
        // satisfied without terminal interaction. *u must be a
        // const std::string* holding the PIN.
        int pinPasswordCallback(char* buf, int size, int rwflag, void* u);

        // RAII holder for a private OpenSSL library context with the default and
        // pkcs11 providers loaded. Confines the pkcs11-provider to a single
        // operation, keeps it off the process-wide default context, and removes
        // any dependency on it being activated in the system openssl.cnf.
        //
        // Any EVP_PKEY obtained from libctx must be freed by the caller BEFORE
        // the Context is destroyed.
        struct Context {
            OSSL_LIB_CTX* libctx = nullptr;
            OSSL_PROVIDER* defProv = nullptr;
            OSSL_PROVIDER* p11Prov = nullptr;

            Context() = default;
            Context(const Context&) = delete;
            Context& operator=(const Context&) = delete;
            ~Context();

            // Returns true once the pkcs11 provider is loaded and ready.
            bool load();
        };

    } // namespace pkcs11
} // namespace provisioner
