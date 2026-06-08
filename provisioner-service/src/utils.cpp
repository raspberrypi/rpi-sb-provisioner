#include "utils.h"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <regex>
#include <functional>
#include <cstring>
#include <cctype>
#include <drogon/drogon.h>
#include "include/audit.h"
#include "keywrap.h"
#include <openssl/pem.h>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <openssl/bn.h>
#include <openssl/core_names.h>
#include <openssl/store.h>
#include <openssl/ui.h>
#include <openssl/provider.h>
#include <openssl/crypto.h>
#include <openssl/err.h>

namespace provisioner {
    namespace utils {
        
        
        constexpr const char* FIRMWARE_BASE_PATH = "/lib/firmware/raspberrypi/bootloader-";
        
        // ===== Firmware Scanning Implementation =====
        
        std::vector<FirmwareInfo> scanFirmwareDirectory(const std::string& deviceFamily) {
            std::vector<FirmwareInfo> firmwareList;
            
            std::string chipNumber = getChipNumberForFamily(deviceFamily);
            if (chipNumber.empty()) {
                LOG_WARN << "Unknown device family for firmware scan: " << deviceFamily;
                return firmwareList;
            }
            
            std::string firmwareDir = std::string(FIRMWARE_BASE_PATH) + chipNumber;
            
            if (!std::filesystem::exists(firmwareDir)) {
                LOG_WARN << "Firmware directory does not exist: " << firmwareDir;
                return firmwareList;
            }
            
            // Release directories in priority order
            std::vector<std::string> releaseDirs = {"default", "latest", "beta", "stable", "critical"};
            
            // Map version to (channel, filepath) pairs
            std::map<std::string, std::vector<std::pair<std::string, std::string>>> versionToChannelsAndPaths;
            
            // Scan all release directories
            for (const auto& releaseDir : releaseDirs) {
                std::string releasePath = firmwareDir + "/" + releaseDir;
                if (!std::filesystem::exists(releasePath) || !std::filesystem::is_directory(releasePath)) {
                    continue;
                }
                
                try {
                    for (const auto& entry : std::filesystem::directory_iterator(releasePath)) {
                        if (!entry.is_regular_file()) continue;
                        
                        std::string filename = entry.path().filename().string();
                        if (filename.find("pieeprom-") != 0 || !filename.ends_with(".bin")) {
                            continue;
                        }
                        
                        // Extract version from filename (e.g., pieeprom-2024-01-15.bin -> 2024-01-15)
                        std::regex versionRegex(R"(pieeprom-(\d{4}-\d{2}-\d{2})\.bin)");
                        std::smatch match;
                        if (std::regex_search(filename, match, versionRegex)) {
                            std::string version = match[1].str();
                            versionToChannelsAndPaths[version].push_back({releaseDir, entry.path().string()});
                        }
                    }
                } catch (const std::filesystem::filesystem_error& e) {
                    LOG_ERROR << "Error scanning firmware directory " << releasePath << ": " << e.what();
                }
            }
            
            // Build firmware list with preferred channel for each version
            for (const auto& [version, channelsAndPaths] : versionToChannelsAndPaths) {
                std::string preferredChannel;
                std::string preferredFilepath;
                
                // Find the highest priority channel for this version
                for (const auto& preferredOrder : releaseDirs) {
                    for (const auto& [channel, filepath] : channelsAndPaths) {
                        if (channel == preferredOrder) {
                            preferredChannel = channel;
                            preferredFilepath = filepath;
                            break;
                        }
                    }
                    if (!preferredChannel.empty()) break;
                }
                
                if (!preferredChannel.empty()) {
                    FirmwareInfo info;
                    info.version = version;
                    info.filename = std::filesystem::path(preferredFilepath).filename().string();
                    
                    // Canonicalize the filepath to match how it's stored in config
                    try {
                        info.filepath = std::filesystem::canonical(preferredFilepath).string();
                    } catch (const std::filesystem::filesystem_error&) {
                        info.filepath = preferredFilepath;
                    }
                    
                    info.releaseChannel = preferredChannel;
                    
                    try {
                        info.size = std::filesystem::file_size(preferredFilepath);
                    } catch (const std::filesystem::filesystem_error&) {
                        info.size = 0;
                    }
                    
                    firmwareList.push_back(info);
                }
            }
            
            // Sort by version (newest first)
            std::sort(firmwareList.begin(), firmwareList.end(),
                [](const FirmwareInfo& a, const FirmwareInfo& b) {
                    return a.version > b.version;
                });
            
            LOG_INFO << "Scanned firmware directory for family " << deviceFamily 
                     << ": found " << firmwareList.size() << " versions";
            
            return firmwareList;
        }
        
        // ===== Key Parsing Implementation =====
        
        namespace {
            // Read the stored PKCS#11 PIN so it can be handed to the provider
            // in-process via the passphrase callback, rather than written into
            // a pin-source= file referenced on a command line. Returns empty if
            // no PIN is configured or it cannot be read.
            std::string readStoredPkcs11Pin() {
                if (!std::filesystem::exists(PKCS11_PIN_FILE)) {
                    return {};
                }
                std::ifstream pinFile(PKCS11_PIN_FILE, std::ios::binary);
                if (!pinFile.is_open()) {
                    return {};
                }
                std::string raw((std::istreambuf_iterator<char>(pinFile)),
                                std::istreambuf_iterator<char>());

                // PINs are stored device-wrapped at rest (see savePkcs11Pin).
                // A blob without the wrap magic is a legacy plaintext PIN from
                // before wrapping existed: read it as-is so the install keeps
                // working; it is re-wrapped the next time the PIN is saved.
                std::string pin;
                if (keywrap::isWrapped(raw)) {
                    if (!keywrap::unwrap(raw, pin)) {
                        LOG_ERROR << "Failed to unwrap stored PKCS#11 PIN "
                                     "(wrong device or corrupt file)";
                        return {};
                    }
                } else {
                    LOG_WARN << "PKCS#11 PIN is stored unwrapped (legacy); "
                                "re-save it to wrap at rest";
                    pin = raw;
                }

                // The PIN is stored without a trailing newline, but strip any
                // stray trailing whitespace defensively.
                while (!pin.empty() && (pin.back() == '\n' || pin.back() == '\r')) {
                    pin.pop_back();
                }
                return pin;
            }

            // pem_password_cb that copies a PIN held in *u into OpenSSL's buffer.
            // Wrapped into a UI_METHOD via UI_UTIL_wrap_read_pem_callback so it
            // satisfies OSSL_STORE's passphrase prompts (and thus the
            // pkcs11-provider's C_Login) without any terminal interaction.
            int pinPasswordCallback(char* buf, int size, int /*rwflag*/, void* u) {
                const auto* pin = static_cast<const std::string*>(u);
                if (!pin || pin->empty() || size <= 0) {
                    return 0;
                }
                int len = static_cast<int>(std::min(pin->size(), static_cast<size_t>(size)));
                std::memcpy(buf, pin->data(), static_cast<size_t>(len));
                return len;
            }

            // Drain the OpenSSL error queue into a single string. Used only to
            // CLASSIFY failures into a user-facing category; the raw text is
            // never logged, as it can leak HSM/token detail.
            std::string drainOpenSslErrors() {
                std::string out;
                unsigned long err;
                char buf[256];
                while ((err = ERR_get_error()) != 0) {
                    ERR_error_string_n(err, buf, sizeof(buf));
                    if (!out.empty()) {
                        out += "; ";
                    }
                    out += buf;
                }
                return out;
            }

            // RAII holder for a private library context with the default and
            // pkcs11 providers loaded. Keeps the pkcs11-provider confined to the
            // operation that needs it and off the process-wide default context
            // (libcurl TLS, the PEM key path), and removes any dependency on the
            // provider being activated in the system openssl.cnf.
            struct Pkcs11Context {
                OSSL_LIB_CTX* libctx = nullptr;
                OSSL_PROVIDER* defProv = nullptr;
                OSSL_PROVIDER* p11Prov = nullptr;

                Pkcs11Context() = default;
                Pkcs11Context(const Pkcs11Context&) = delete;
                Pkcs11Context& operator=(const Pkcs11Context&) = delete;

                // Returns true once the pkcs11 provider is loaded and ready.
                bool load() {
                    libctx = OSSL_LIB_CTX_new();
                    if (!libctx) {
                        return false;
                    }
                    defProv = OSSL_PROVIDER_load(libctx, "default");
                    p11Prov = OSSL_PROVIDER_load(libctx, "pkcs11");
                    return p11Prov != nullptr;
                }

                ~Pkcs11Context() {
                    // Providers must be unloaded before the context is freed;
                    // any EVP_PKEY obtained from the context must already be
                    // freed by the caller before this runs.
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
            };

            // Percent-decode a PKCS#11 URI component for display (e.g. a token
            // label "My%20Token" -> "My Token"). Leaves malformed escapes as-is.
            std::string pctDecode(const std::string& s) {
                std::string out;
                out.reserve(s.size());
                auto hexVal = [](char c) {
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                    return c <= '9' ? c - '0' : c - 'a' + 10;
                };
                for (size_t i = 0; i < s.size(); ++i) {
                    if (s[i] == '%' && i + 2 < s.size() &&
                        std::isxdigit(static_cast<unsigned char>(s[i + 1])) &&
                        std::isxdigit(static_cast<unsigned char>(s[i + 2]))) {
                        out.push_back(static_cast<char>(hexVal(s[i + 1]) * 16 + hexVal(s[i + 2])));
                        i += 2;
                    } else {
                        out.push_back(s[i]);
                    }
                }
                return out;
            }

            // Extract a single attribute (e.g. "object", "token", "type") from
            // the path part of a pkcs11: URI, percent-decoded. Returns empty if
            // the attribute is absent.
            std::string pkcs11UriAttr(const std::string& uri, const std::string& key) {
                std::string path = uri;
                auto q = path.find('?');               // drop any query component
                if (q != std::string::npos) {
                    path = path.substr(0, q);
                }
                const std::string scheme = "pkcs11:";
                if (path.rfind(scheme, 0) == 0) {
                    path = path.substr(scheme.size());
                }
                size_t start = 0;
                while (start <= path.size()) {
                    size_t semi = path.find(';', start);
                    std::string attr = path.substr(start,
                        semi == std::string::npos ? std::string::npos : semi - start);
                    auto eq = attr.find('=');
                    if (eq != std::string::npos && attr.substr(0, eq) == key) {
                        return pctDecode(attr.substr(eq + 1));
                    }
                    if (semi == std::string::npos) {
                        break;
                    }
                    start = semi + 1;
                }
                return {};
            }

            // Parse a discovered pkcs11: URI into the fields the UI needs.
            Pkcs11Object parsePkcs11ObjectUri(const std::string& uri) {
                Pkcs11Object obj;
                obj.uri = uri;
                obj.label = pkcs11UriAttr(uri, "object");
                obj.token = pkcs11UriAttr(uri, "token");
                obj.type = pkcs11UriAttr(uri, "type");
                return obj;
            }

            // Compute the Raspberry Pi secure-boot key hash for an RSA key.
            //
            // This is the value the bootloader programs into device OTP and uses
            // to authenticate the signed boot image, NOT a generic SHA256 of the
            // PEM/DER encoding. It must match the calculation in usbboot's
            // rpi-sign-bootcode (append_public_key):
            //
            //     SHA256( n.to_bytes(256, 'little') || e.to_bytes(8, 'little') )
            //
            // where n is the 2048-bit modulus and e the public exponent. The
            // fixed 256/8 byte widths mean this is only defined for RSA-2048
            // keys (the only key type valid for Pi secure boot); an empty
            // string is returned for anything else. The modulus and exponent
            // are public components, so a private-key EVP_PKEY works here too.
            std::string computeSecureBootKeyHash(EVP_PKEY* pkey) {
                std::string result;
                if (!pkey) {
                    return result;
                }

                if (EVP_PKEY_base_id(pkey) == EVP_PKEY_RSA &&
                    EVP_PKEY_bits(pkey) == 2048) {
                    BIGNUM* n = nullptr;
                    BIGNUM* e = nullptr;
                    if (EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_N, &n) == 1 &&
                        EVP_PKEY_get_bn_param(pkey, OSSL_PKEY_PARAM_RSA_E, &e) == 1) {
                        // 256 bytes of little-endian modulus followed by 8 bytes
                        // of little-endian exponent, matching the bootloader.
                        unsigned char buf[256 + 8];
                        if (BN_bn2lebinpad(n, buf, 256) == 256 &&
                            BN_bn2lebinpad(e, buf + 256, 8) == 8) {
                            unsigned char digest[SHA256_DIGEST_LENGTH];
                            SHA256(buf, sizeof(buf), digest);

                            static const char hex[] = "0123456789abcdef";
                            result.reserve(SHA256_DIGEST_LENGTH * 2);
                            for (unsigned char byte : digest) {
                                result.push_back(hex[byte >> 4]);
                                result.push_back(hex[byte & 0x0f]);
                            }
                        }
                    }
                    BN_free(n);
                    BN_free(e);
                }

                return result;
            }

            // Convenience overload: parse a PEM-encoded public key and hash it.
            // Used by the PKCS#11 path, which still obtains the public key as PEM.
            std::string computeSecureBootKeyHash(const std::string& publicKeyPem) {
                BIO* bio = BIO_new_mem_buf(publicKeyPem.data(),
                                           static_cast<int>(publicKeyPem.size()));
                if (!bio) {
                    return {};
                }
                EVP_PKEY* pkey = PEM_read_bio_PUBKEY(bio, nullptr, nullptr, nullptr);
                BIO_free(bio);

                std::string result = computeSecureBootKeyHash(pkey);
                EVP_PKEY_free(pkey);
                return result;
            }

            // Determine fitness for purpose from an already-populated algorithm
            // and keySize (Pi secure boot requires RSA-2048). Shared by the
            // PEM (library) and PKCS#11 (text) parsing paths so the policy
            // lives in one place.
            void setFitnessForPurpose(KeyInfo& info) {
                if (info.algorithm == "RSA" && info.keySize == 2048) {
                    info.isFitForPurpose = true;
                    info.statusLevel = "valid";
                    info.statusMessage = "Valid for secure boot";
                } else if (info.algorithm == "RSA" && info.keySize > 0) {
                    info.isFitForPurpose = false;
                    info.statusLevel = "error";
                    info.statusMessage = "Pi secure boot requires RSA-2048 (key is RSA-" +
                                         std::to_string(info.keySize) + ")";
                } else if (info.algorithm != "RSA") {
                    info.isFitForPurpose = false;
                    info.statusLevel = "error";
                    info.statusMessage = "Unsupported: Pi secure boot requires RSA";
                } else {
                    info.isFitForPurpose = false;
                    info.statusLevel = "error";
                    info.statusMessage = "Could not determine key type";
                }
            }

            // Populate a KeyInfo directly from a parsed EVP_PKEY, using the
            // linked OpenSSL library rather than scraping `openssl ... -text`
            // output. The key type and size come back as values, so there is
            // no human-readable format to regex against.
            KeyInfo describeKey(EVP_PKEY* pkey) {
                KeyInfo info;
                info.success = true;
                info.isPrivateKey = true;  // We're always checking private keys

                switch (EVP_PKEY_base_id(pkey)) {
                    case EVP_PKEY_RSA:
                    case EVP_PKEY_RSA_PSS:
                        info.algorithm = "RSA";
                        break;
                    case EVP_PKEY_EC:
                        info.algorithm = "EC";
                        break;
                    case EVP_PKEY_DSA:
                        info.algorithm = "DSA";
                        break;
                    default:
                        info.algorithm = "Unknown";
                        break;
                }
                info.keySize = EVP_PKEY_bits(pkey);

                setFitnessForPurpose(info);
                return info;
            }
        }
        
        KeyInfo parseKeyFile(const std::string& path) {
            KeyInfo info;
            
            // Validate file exists
            if (!std::filesystem::exists(path)) {
                info.success = false;
                info.errorMessage = "Key file not found";
                info.statusLevel = "error";
                info.statusMessage = "Key file not found";
                return info;
            }
            
            // Read the key file into memory. Customer keys are stored
            // device-wrapped at rest (see the /upload-key handler); unwrap
            // transparently so the UI can still describe a stored key. A blob
            // without the wrap magic is parsed directly (legacy plaintext, or a
            // key just uploaded and not yet wrapped).
            std::ifstream keyIn(path, std::ios::binary);
            if (!keyIn.is_open()) {
                info.success = false;
                info.errorMessage = "Failed to open key file";
                info.statusLevel = "error";
                info.statusMessage = "Invalid key format";
                LOG_WARN << "Failed to open key file: " << path;
                return info;
            }
            std::string raw((std::istreambuf_iterator<char>(keyIn)),
                            std::istreambuf_iterator<char>());
            keyIn.close();

            std::string pem;
            if (keywrap::isWrapped(raw)) {
                if (!keywrap::unwrap(raw, pem)) {
                    info.success = false;
                    info.errorMessage = "Failed to unwrap key (wrong device or corrupt file)";
                    info.statusLevel = "error";
                    info.statusMessage = "Invalid key format";
                    LOG_WARN << "Failed to unwrap key file: " << path;
                    return info;
                }
            } else {
                pem = raw;
            }

            // Parse the key with the linked OpenSSL library instead of shelling
            // out to the `openssl` CLI. PEM_read_bio_PrivateKey handles RSA, EC
            // and any other PEM private key in one call (traditional or PKCS#8),
            // replacing the previous rsa/ec/pkey CLI fallback chain.
            BIO* bio = BIO_new_mem_buf(pem.data(), static_cast<int>(pem.size()));
            if (!bio) {
                if (!pem.empty()) OPENSSL_cleanse(&pem[0], pem.size());
                info.success = false;
                info.errorMessage = "Failed to open key file";
                info.statusLevel = "error";
                info.statusMessage = "Invalid key format";
                LOG_WARN << "Failed to open key file: " << path;
                return info;
            }

            // Never block on a passphrase prompt: this runs in a daemon with no
            // controlling terminal, and the previous CLI calls supplied no
            // passphrase either. A callback returning 0 makes an encrypted key
            // fail to parse rather than hang waiting on /dev/tty.
            auto noPrompt = [](char*, int, int, void*) -> int { return 0; };
            EVP_PKEY* pkey = PEM_read_bio_PrivateKey(bio, nullptr, noPrompt, nullptr);
            BIO_free(bio);
            if (!pem.empty()) OPENSSL_cleanse(&pem[0], pem.size());

            if (!pkey) {
                info.success = false;
                info.errorMessage = "Failed to parse key file";
                info.statusLevel = "error";
                info.statusMessage = "Invalid key format";
                LOG_WARN << "Failed to parse key file: " << path;
                return info;
            }

            info = describeKey(pkey);

            // Compute the secure-boot key hash (the value programmed into device
            // OTP) so the UI shows a hash directly comparable to the device. The
            // modulus and exponent are public components of the private key, so
            // no separate public-key derivation is needed. See
            // computeSecureBootKeyHash() for the exact calculation.
            info.fingerprint = computeSecureBootKeyHash(pkey);

            EVP_PKEY_free(pkey);

            LOG_INFO << "Parsed key: " << info.algorithm << "-" << info.keySize
                     << " (" << info.statusLevel << ")";
            return info;
        }
        
        KeyInfo parsePkcs11Key(const std::string& uri, const std::string& pin) {
            KeyInfo info;

            // Validate URI format
            if (uri.find("pkcs11:") != 0) {
                info.success = false;
                info.errorMessage = "Invalid PKCS#11 URI format";
                info.statusLevel = "error";
                info.statusMessage = "Invalid URI format";
                return info;
            }

            // Load the pkcs11-provider (plus the default provider, for hashing
            // and RSA parameter access) into a PRIVATE library context, and
            // query the key through OSSL_STORE. This replaces the deprecated
            // `openssl rsa -engine pkcs11` ENGINE path. Using a private context
            // confines the provider to this operation: the process-wide default
            // context (libcurl TLS, the PEM key path) is left untouched, and we
            // do not depend on the provider being activated in the system
            // openssl.cnf -- matching the explicit `-provider pkcs11 -provider
            // default` flags used by the signing scripts.
            OSSL_LIB_CTX* libctx = OSSL_LIB_CTX_new();
            if (!libctx) {
                info.success = false;
                info.errorMessage = "Failed to create OpenSSL context";
                info.statusLevel = "error";
                info.statusMessage = "Internal error";
                return info;
            }
            OSSL_PROVIDER* defProv = OSSL_PROVIDER_load(libctx, "default");
            OSSL_PROVIDER* p11Prov = OSSL_PROVIDER_load(libctx, "pkcs11");
            if (!p11Prov) {
                if (defProv) {
                    OSSL_PROVIDER_unload(defProv);
                }
                OSSL_LIB_CTX_free(libctx);
                info.success = false;
                info.errorMessage = "PKCS#11 provider not available";
                info.statusLevel = "error";
                info.statusMessage = "PKCS#11 provider not installed";
                LOG_WARN << "Failed to parse PKCS#11 key: " << info.statusMessage;
                return info;
            }

            // Resolve the PIN: an explicitly supplied PIN (validation flow) wins,
            // otherwise fall back to the stored PIN if one is configured. It is
            // handed to the provider in-process via the passphrase callback,
            // never written to a pin-source= file referenced on a command line.
            std::string effectivePin = !pin.empty() ? pin : readStoredPkcs11Pin();

            UI_METHOD* uiMethod = UI_UTIL_wrap_read_pem_callback(pinPasswordCallback, 0);
            if (!uiMethod) {
                OSSL_PROVIDER_unload(p11Prov);
                if (defProv) {
                    OSSL_PROVIDER_unload(defProv);
                }
                OSSL_LIB_CTX_free(libctx);
                info.success = false;
                info.errorMessage = "Failed to set up PIN handling";
                info.statusLevel = "error";
                info.statusMessage = "Internal error";
                return info;
            }

            // Clear stale errors so the failure classifier below only sees
            // errors produced by this call.
            ERR_clear_error();

            EVP_PKEY* pkey = nullptr;
            OSSL_STORE_CTX* ctx = OSSL_STORE_open_ex(uri.c_str(), libctx, nullptr,
                                                     uiMethod, &effectivePin,
                                                     nullptr, nullptr, nullptr);
            if (ctx) {
                // We only care about a key object; biasing the store avoids
                // pulling in certificates or other associated objects.
                OSSL_STORE_expect(ctx, OSSL_STORE_INFO_PKEY);
                while (pkey == nullptr && OSSL_STORE_eof(ctx) != 1) {
                    OSSL_STORE_INFO* storeInfo = OSSL_STORE_load(ctx);
                    if (!storeInfo) {
                        // NULL means either an error or a skippable item. Break on
                        // an unrecoverable error so we never spin; otherwise keep
                        // going until EOF.
                        if (OSSL_STORE_error(ctx) == 1) {
                            break;
                        }
                        continue;
                    }
                    switch (OSSL_STORE_INFO_get_type(storeInfo)) {
                        case OSSL_STORE_INFO_PKEY:
                            pkey = OSSL_STORE_INFO_get1_PKEY(storeInfo);
                            break;
                        case OSSL_STORE_INFO_PUBKEY:
                            pkey = OSSL_STORE_INFO_get1_PUBKEY(storeInfo);
                            break;
                        default:
                            break;
                    }
                    OSSL_STORE_INFO_free(storeInfo);
                }
                OSSL_STORE_close(ctx);
            }

            // Extract everything we need while the providers are still loaded
            // (the key is bound to the private library context).
            bool parsed = false;
            if (pkey) {
                info = describeKey(pkey);

                // The RSA modulus and exponent are public components, so the
                // secure-boot key hash (the OTP value) can be computed directly
                // from the key handle without a separate public-key export.
                info.fingerprint = computeSecureBootKeyHash(pkey);
                EVP_PKEY_free(pkey);
                parsed = true;
            }

            // Capture failure detail from the error queue before tearing down
            // the OpenSSL state. SECURITY: the raw error text can carry HSM/token
            // detail, so it is only inspected here and never logged.
            std::string errText = parsed ? std::string() : drainOpenSslErrors();

            UI_destroy_method(uiMethod);
            OSSL_PROVIDER_unload(p11Prov);
            if (defProv) {
                OSSL_PROVIDER_unload(defProv);
            }
            OSSL_LIB_CTX_free(libctx);

            if (parsed) {
                LOG_INFO << "Parsed PKCS#11 key: " << info.algorithm << "-" << info.keySize
                         << " (" << info.statusLevel << ")";
                return info;
            }

            // Classify the failure into a user-facing category.
            auto contains = [&errText](const char* needle) {
                return errText.find(needle) != std::string::npos;
            };

            info.success = false;
            info.statusLevel = "error";
            if (contains("PIN") || contains("pin") || contains("login") ||
                contains("authenticat") || contains("CKR_PIN")) {
                info.errorMessage = "PIN incorrect or not provided";
                info.statusMessage = "Invalid PIN";
            } else if (contains("token") || contains("slot") || contains("CKR_TOKEN") ||
                       contains("CKR_SLOT") || contains("CKR_DEVICE")) {
                info.errorMessage = "Cannot access HSM - check connection";
                info.statusMessage = "Cannot access HSM";
            } else if (contains("object") || contains("not found") || contains("CKR_OBJECT")) {
                info.errorMessage = "Key not found on HSM";
                info.statusMessage = "Key not found on HSM";
            } else {
                info.errorMessage = "Failed to access PKCS#11 key";
                info.statusMessage = "Cannot access HSM - check connection";
            }

            LOG_WARN << "Failed to parse PKCS#11 key: " << info.statusMessage;
            return info;
        }

        bool isPkcs11ProviderAvailable() {
            // Loading the provider into a throwaway private context is a cheap,
            // side-effect-free probe: it touches no token, so it never needs a
            // PIN, and leaves the process-wide default context untouched.
            Pkcs11Context octx;
            return octx.load();
        }

        Pkcs11Discovery discoverPkcs11(const std::string& pin) {
            Pkcs11Discovery result;

            Pkcs11Context octx;
            if (!octx.load()) {
                result.providerAvailable = false;
                result.errorMessage = "PKCS#11 provider not installed";
                return result;
            }
            result.providerAvailable = true;

            // Some tokens require a login before private objects are listed, so
            // supply the PIN (explicit or stored) the same way validation does.
            std::string effectivePin = !pin.empty() ? pin : readStoredPkcs11Pin();
            UI_METHOD* uiMethod = UI_UTIL_wrap_read_pem_callback(pinPasswordCallback, 0);
            if (!uiMethod) {
                result.errorMessage = "Internal error";
                return result;
            }

            ERR_clear_error();

            // Listing the bare "pkcs11:" store yields OSSL_STORE_INFO_NAME
            // entries, each a fully-qualified URI for one object (the same
            // listing `openssl storeutl pkcs11:` produces).
            OSSL_STORE_CTX* sctx = OSSL_STORE_open_ex("pkcs11:", octx.libctx, nullptr,
                                                      uiMethod, &effectivePin,
                                                      nullptr, nullptr, nullptr);
            if (sctx) {
                while (OSSL_STORE_eof(sctx) != 1) {
                    OSSL_STORE_INFO* info = OSSL_STORE_load(sctx);
                    if (!info) {
                        if (OSSL_STORE_error(sctx) == 1) {
                            break;
                        }
                        continue;
                    }
                    if (OSSL_STORE_INFO_get_type(info) == OSSL_STORE_INFO_NAME) {
                        const char* name = OSSL_STORE_INFO_get0_NAME(info);
                        if (name) {
                            result.objects.push_back(parsePkcs11ObjectUri(name));
                        }
                    }
                    OSSL_STORE_INFO_free(info);
                }
                OSSL_STORE_close(sctx);
            }

            UI_destroy_method(uiMethod);

            // If nothing surfaced, classify any error so the UI can guide the
            // user. SECURITY: the raw error text may carry HSM detail and is
            // never logged.
            if (result.objects.empty()) {
                std::string errText = drainOpenSslErrors();
                auto contains = [&errText](const char* needle) {
                    return errText.find(needle) != std::string::npos;
                };
                if (contains("PIN") || contains("pin") || contains("login") ||
                    contains("authenticat") || contains("CKR_PIN")) {
                    result.errorMessage = "A PIN is required to list keys on this token";
                } else if (contains("token") || contains("slot") ||
                           contains("CKR_TOKEN") || contains("CKR_SLOT") ||
                           contains("CKR_DEVICE")) {
                    result.errorMessage = "Cannot access HSM - check connection";
                }
                // Otherwise leave errorMessage empty: provider is present but
                // no keys were found (a normal, non-error state).
            }

            LOG_INFO << "PKCS#11 discovery found " << result.objects.size() << " object(s)";
            return result;
        }

        // ===== PKCS#11 PIN Management Implementation =====
        
        bool isPkcs11PinConfigured() {
            if (!std::filesystem::exists(PKCS11_PIN_FILE)) {
                return false;
            }
            
            try {
                auto size = std::filesystem::file_size(PKCS11_PIN_FILE);
                return size > 0;
            } catch (const std::filesystem::filesystem_error&) {
                return false;
            }
        }
        
        bool savePkcs11Pin(const std::string& pin) {
            // Create the keys directory if it doesn't exist
            std::string keyStorageDir = "/etc/rpi-sb-provisioner/keys";
            try {
                if (!std::filesystem::exists(keyStorageDir)) {
                    std::filesystem::create_directories(keyStorageDir);
                    std::filesystem::permissions(keyStorageDir,
                        std::filesystem::perms::owner_all,
                        std::filesystem::perm_options::replace);
                }
            } catch (const std::filesystem::filesystem_error& e) {
                LOG_ERROR << "Failed to create keys directory: " << e.what();
                return false;
            }
            
            // Wrap the PIN with the device-bound key before it touches disk.
            // On this Pi-only deployment wrapping must succeed; refuse rather
            // than silently fall back to storing the PIN in plaintext.
            std::string blob;
            if (!keywrap::wrap(pin, blob)) {
                LOG_ERROR << "Failed to device-wrap PKCS#11 PIN; refusing to store it";
                return false;
            }

            // Write the wrapped blob (binary).
            std::ofstream pinFile(PKCS11_PIN_FILE, std::ios::binary);
            if (!pinFile.is_open()) {
                LOG_ERROR << "Failed to open PIN file for writing: " << PKCS11_PIN_FILE;
                return false;
            }
            pinFile.write(blob.data(), static_cast<std::streamsize>(blob.size()));
            pinFile.close();
            
            // Set restrictive permissions (owner read-only)
            try {
                std::filesystem::permissions(PKCS11_PIN_FILE,
                    std::filesystem::perms::owner_read,
                    std::filesystem::perm_options::replace);
            } catch (const std::filesystem::filesystem_error& e) {
                LOG_ERROR << "Failed to set PIN file permissions: " << e.what();
                // Try to remove the file if we can't set permissions
                std::filesystem::remove(PKCS11_PIN_FILE);
                return false;
            }
            
            LOG_INFO << "PKCS#11 PIN saved securely";
            AuditLog::logFileSystemAccess("WRITE_PIN", PKCS11_PIN_FILE, true);
            return true;
        }
        
        bool removePkcs11Pin() {
            if (!std::filesystem::exists(PKCS11_PIN_FILE)) {
                return true;  // Already doesn't exist
            }
            
            try {
                std::filesystem::remove(PKCS11_PIN_FILE);
                LOG_INFO << "PKCS#11 PIN file removed";
                AuditLog::logFileSystemAccess("DELETE_PIN", PKCS11_PIN_FILE, true);
                return true;
            } catch (const std::filesystem::filesystem_error& e) {
                LOG_ERROR << "Failed to remove PIN file: " << e.what();
                return false;
            }
        }

        bool isFileDeviceWrapped(const std::string& path) {
            std::ifstream f(path, std::ios::binary);
            if (!f.is_open()) {
                return false;
            }
            // Only the magic header is needed to classify the file.
            char hdr[8] = {0};
            f.read(hdr, sizeof(hdr));
            std::string head(hdr, static_cast<size_t>(f.gcount()));
            return keywrap::isWrapped(head);
        }

        bool wrapFileInPlace(const std::string& path) {
            if (!std::filesystem::exists(path)) {
                return false;
            }

            std::ifstream in(path, std::ios::binary);
            if (!in.is_open()) {
                LOG_ERROR << "Migration: cannot read secret file: " << path;
                return false;
            }
            std::string raw((std::istreambuf_iterator<char>(in)),
                            std::istreambuf_iterator<char>());
            in.close();

            if (raw.empty()) {
                return false;
            }
            if (keywrap::isWrapped(raw)) {
                return true; // already migrated; nothing to do
            }

            std::string blob;
            if (!keywrap::wrap(raw, blob)) {
                if (!raw.empty()) OPENSSL_cleanse(&raw[0], raw.size());
                LOG_ERROR << "Migration: failed to device-wrap secret: " << path;
                return false;
            }
            if (!raw.empty()) OPENSSL_cleanse(&raw[0], raw.size());

            std::ofstream out(path, std::ios::binary | std::ios::trunc);
            if (!out.is_open()) {
                LOG_ERROR << "Migration: cannot write wrapped secret: " << path;
                return false;
            }
            out.write(blob.data(), static_cast<std::streamsize>(blob.size()));
            out.close();

            try {
                std::filesystem::permissions(path,
                    std::filesystem::perms::owner_read,
                    std::filesystem::perm_options::replace);
            } catch (const std::filesystem::filesystem_error& e) {
                LOG_ERROR << "Migration: failed to set permissions on " << path << ": " << e.what();
                return false;
            }

            LOG_INFO << "Migration: wrapped secret at rest: " << path;
            AuditLog::logFileSystemAccess("WRAP_SECRET", path, true);
            return true;
        }

        bool hasUnwrappedSecretsAtRest() {
            if (isPkcs11PinConfigured() && !isFileDeviceWrapped(PKCS11_PIN_FILE)) {
                return true;
            }
            auto keyPathOpt = getConfigValue("CUSTOMER_KEY_FILE_PEM");
            if (keyPathOpt && !keyPathOpt->empty()
                && std::filesystem::exists(*keyPathOpt)
                && !isFileDeviceWrapped(*keyPathOpt)) {
                return true;
            }
            return false;
        }
        
        // ===== CSRF Token Implementation =====
        
        CsrfTokenManager& CsrfTokenManager::getInstance() {
            static CsrfTokenManager instance;
            return instance;
        }
        
        std::string CsrfTokenManager::generateToken(const std::string& sessionId) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            // Generate random token
            static const char charset[] = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789";
            static std::random_device rd;
            static std::mt19937 gen(rd());
            static std::uniform_int_distribution<> dis(0, sizeof(charset) - 2);
            
            std::string token;
            token.reserve(TOKEN_LENGTH);
            for (int i = 0; i < TOKEN_LENGTH; ++i) {
                token += charset[dis(gen)];
            }
            
            // Store the token
            TokenInfo tokenInfo;
            tokenInfo.token = token;
            tokenInfo.createdAt = std::chrono::steady_clock::now();
            tokenInfo.used = false;
            
            auto& tokens = sessionTokens_[sessionId];
            
            // Limit tokens per session
            if (tokens.size() >= MAX_TOKENS_PER_SESSION) {
                tokens.erase(tokens.begin());
            }
            
            tokens.push_back(tokenInfo);
            
            LOG_DEBUG << "Generated CSRF token for session " << sessionId.substr(0, 8) << "...";
            
            return token;
        }
        
        bool CsrfTokenManager::validateToken(const std::string& sessionId, const std::string& token) {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto sessionIt = sessionTokens_.find(sessionId);
            if (sessionIt == sessionTokens_.end()) {
                LOG_WARN << "CSRF validation failed: unknown session " << sessionId.substr(0, 8) << "...";
                return false;
            }
            
            auto now = std::chrono::steady_clock::now();
            
            for (auto& tokenInfo : sessionIt->second) {
                if (tokenInfo.token == token) {
                    // Check if expired
                    auto age = std::chrono::duration_cast<std::chrono::seconds>(now - tokenInfo.createdAt).count();
                    if (age > TOKEN_VALIDITY_SECONDS) {
                        LOG_WARN << "CSRF validation failed: token expired (age: " << age << "s)";
                        return false;
                    }
                    
                    // Token is valid - mark as used but allow reuse within the validity period
                    // (for AJAX apps where multiple requests might use the same token)
                    tokenInfo.used = true;
                    LOG_DEBUG << "CSRF token validated for session " << sessionId.substr(0, 8) << "...";
                    return true;
                }
            }
            
            LOG_WARN << "CSRF validation failed: token not found for session " << sessionId.substr(0, 8) << "...";
            return false;
        }
        
        void CsrfTokenManager::cleanupExpiredTokens() {
            std::lock_guard<std::mutex> lock(mutex_);
            
            auto now = std::chrono::steady_clock::now();
            int removedCount = 0;
            
            for (auto sessionIt = sessionTokens_.begin(); sessionIt != sessionTokens_.end();) {
                auto& tokens = sessionIt->second;
                
                // Remove expired tokens
                tokens.erase(
                    std::remove_if(tokens.begin(), tokens.end(),
                        [&now, &removedCount](const TokenInfo& info) {
                            auto age = std::chrono::duration_cast<std::chrono::seconds>(now - info.createdAt).count();
                            if (age > TOKEN_VALIDITY_SECONDS) {
                                removedCount++;
                                return true;
                            }
                            return false;
                        }),
                    tokens.end()
                );
                
                // Remove empty sessions
                if (tokens.empty()) {
                    sessionIt = sessionTokens_.erase(sessionIt);
                } else {
                    ++sessionIt;
                }
            }
            
            if (removedCount > 0) {
                LOG_DEBUG << "CSRF cleanup: removed " << removedCount << " expired tokens";
            }
        }
        
        std::string getSessionIdFromRequest(const drogon::HttpRequestPtr& req) {
            // Create a session ID from IP + User-Agent
            std::string ip = req->getPeerAddr().toIp();
            std::string userAgent = req->getHeader("User-Agent");
            
            // Simple hash combination
            std::hash<std::string> hasher;
            size_t hash = hasher(ip) ^ (hasher(userAgent) << 1);
            
            return std::to_string(hash);
        }
        
        bool validateCsrfToken(const drogon::HttpRequestPtr& req) {
            // Check X-CSRF-Token header first
            std::string token = req->getHeader("X-CSRF-Token");
            
            // If not in header, check request body for JSON requests
            if (token.empty()) {
                auto jsonBody = req->getJsonObject();
                if (jsonBody && jsonBody->isMember("_csrf_token")) {
                    token = (*jsonBody)["_csrf_token"].asString();
                }
            }
            
            if (token.empty()) {
                LOG_WARN << "CSRF validation failed: no token provided";
                return false;
            }
            
            std::string sessionId = getSessionIdFromRequest(req);
            return CsrfTokenManager::getInstance().validateToken(sessionId, token);
        }
        
        std::optional<std::string> getConfigValue(const std::string& key, bool logAccessToAudit) {
            std::optional<std::string> result = std::nullopt;
            
            // Helper lambda to search a config file for a key
            auto searchFile = [&key](const std::string& filepath) -> std::optional<std::string> {
                std::ifstream configFile(filepath);
                if (!configFile.is_open()) {
                    return std::nullopt;
                }
                
                std::string line;
                while (std::getline(configFile, line)) {
                    // Skip commented lines
                    if (!line.empty() && line[0] == '#') {
                        continue;
                    }
                    
                    size_t delimiter_pos = line.find('=');
                    if (delimiter_pos != std::string::npos) {
                        std::string current_key = line.substr(0, delimiter_pos);
                        if (current_key == key) {
                            return line.substr(delimiter_pos + 1);
                        }
                    }
                }
                return std::nullopt;
            };
            
            // Read from defaults first
            result = searchFile(CONFIG_DEFAULTS_PATH);
            if (logAccessToAudit && std::filesystem::exists(CONFIG_DEFAULTS_PATH)) {
                AuditLog::logFileSystemAccess("READ", CONFIG_DEFAULTS_PATH, true);
            }
            
            // Override with user config if present
            auto userValue = searchFile(CONFIG_USER_PATH);
            if (userValue.has_value()) {
                result = userValue;
            }
            
            if (logAccessToAudit) {
                if (std::filesystem::exists(CONFIG_USER_PATH)) {
                    AuditLog::logFileSystemAccess("READ", CONFIG_USER_PATH, true);
                }
            }
            
            if (!result.has_value()) {
                LOG_DEBUG << "Config key not found: " << key;
            }
            
            return result;
        }
        
        std::map<std::string, std::string> getAllConfigValues(bool logAccessToAudit) {
            std::map<std::string, std::string> configValues;
            
            // Helper lambda to read all values from a config file
            auto readFile = [](const std::string& filepath, std::map<std::string, std::string>& values) -> bool {
                std::ifstream configFile(filepath);
                if (!configFile.is_open()) {
                    return false;
                }
                
                std::string line;
                while (std::getline(configFile, line)) {
                    // Skip commented lines
                    if (!line.empty() && line[0] == '#') {
                        continue;
                    }
                    
                    size_t delimiter_pos = line.find('=');
                    if (delimiter_pos != std::string::npos) {
                        std::string key = line.substr(0, delimiter_pos);
                        std::string value = line.substr(delimiter_pos + 1);
                        values[key] = value;
                    }
                }
                return true;
            };
            
            // Read defaults first
            bool defaultsRead = readFile(CONFIG_DEFAULTS_PATH, configValues);
            if (logAccessToAudit) {
                AuditLog::logFileSystemAccess("READ", CONFIG_DEFAULTS_PATH, defaultsRead);
            }
            if (!defaultsRead) {
                LOG_WARN << "Failed to open defaults config file: " << CONFIG_DEFAULTS_PATH;
            }
            
            // Override with user config values (if file exists)
            if (std::filesystem::exists(CONFIG_USER_PATH)) {
                bool userRead = readFile(CONFIG_USER_PATH, configValues);
                if (logAccessToAudit) {
                    AuditLog::logFileSystemAccess("READ", CONFIG_USER_PATH, userRead);
                }
            }
            
            return configValues;
        }
        
        drogon::HttpResponsePtr createConfigErrorResponse(
            const drogon::HttpRequestPtr& req,
            const std::string& configKey) {
            
            std::string errorMessage = "Failed to read configuration file";
            std::string errorDetails;
            
            if (!configKey.empty()) {
                errorMessage += ": " + configKey;
                errorDetails = "The '" + configKey + "' configuration value was not found or could not be read.";
            }
            
            return createErrorResponse(
                req,
                errorMessage,
                drogon::k500InternalServerError,
                "Configuration Error",
                "CONFIG_READ_ERROR",
                errorDetails
            );
        }
    } // namespace utils
} // namespace provisioner

// Global free function so the compiled CSP views can forward-declare and call
// it at block scope (mirroring the `extern bool g_isPublicBinding;` pattern) -
// a namespaced declaration is not legal inside the view's render function body.
bool rpiHasUnwrappedSecretsAtRest() {
    return provisioner::utils::hasUnwrappedSecretsAtRest();
} 