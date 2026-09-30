#include <drogon/drogon.h>
#include <netinet/tcp.h>
#include <filesystem>
#include <cstdio>
#include <memory>
#include <optional>
#include <regex>
#include <iostream>
#include <getopt.h>
#include <map>
#include <algorithm>
#include <curl/curl.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/x509.h>
#include <openssl/err.h>
#include <arpa/inet.h>
#include <openssl/bn.h>
#include <openssl/rand.h>
#include <openssl/x509v3.h>
#include <fstream>
#include <sstream>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

#include "images.h"
#include "devices.h"
#include "customisation.h"
#include "options.h"
#include <services.h>
#include "manufacturing.h"
#include "include/scantool.h"
#include "include/audit.h"
#include "keywrap.h"
#include "auth.h"

using namespace drogon;

// Function to get the current package version
std::string getPackageVersion() {
    std::string version = "unknown";
    
    FILE* pipe = popen("dpkg-query -f='${Version}' -W rpi-sb-provisioner 2>/dev/null", "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe)) {
            version = buffer;
            // Trim any newlines
            if (!version.empty() && version.back() == '\n') {
                version.pop_back();
            }
        }
        pclose(pipe);
    }
    
    return version;
}

// Callback function for curl
static size_t WriteCallback(void *contents, size_t size, size_t nmemb, std::string *userp) {
    userp->append((char*)contents, size * nmemb);
    return size * nmemb;
}

// Function to check for newer GitHub releases
struct VersionInfo {
    std::string latest;
    bool has_newer;
    std::string release_url;
};

// Parse one dot-separated version component, tolerating a trailing suffix such
// as a Debian revision ("2-1") or a pre-release marker ("3~rc1"), which is what
// std::stoi accepted implicitly. Returns false when the component carries no
// leading digits at all.
static bool parseVersionComponent(const std::string& part, int& value) {
    const size_t end = part.find_first_not_of("0123456789");
    const std::string digits = (end == std::string::npos) ? part : part.substr(0, end);
    if (digits.empty()) {
        return false;
    }
    try {
        value = std::stoi(digits);
    } catch (const std::out_of_range&) {
        return false;
    }
    return true;
}

// Split a dotted version into its numeric components. Returns false if any
// component is unparseable, leaving the caller to decide what a non-version
// string means rather than inventing a number for it.
static bool parseVersion(const std::string& version, std::vector<int>& parts) {
    parts.clear();
    std::stringstream ss(version);
    std::string part;
    while (std::getline(ss, part, '.')) {
        int value = 0;
        if (!parseVersionComponent(part, value)) {
            return false;
        }
        parts.push_back(value);
    }
    return !parts.empty();
}

// Compare semantic versions: -1 if v1 < v2, 0 if equal, 1 if v1 > v2, or
// std::nullopt when either side is not a version at all.
//
// The nullopt case is load-bearing. getPackageVersion() returns "unknown" when
// dpkg-query cannot answer -- which is every run from a build tree with no
// package installed -- and this function used to hand that straight to
// std::stoi, whose std::invalid_argument was caught by nobody and terminated
// the process during startup, before the listener came up.
std::optional<int> compareVersions(const std::string& v1, const std::string& v2) {
    std::vector<int> version1, version2;
    if (!parseVersion(v1, version1) || !parseVersion(v2, version2)) {
        return std::nullopt;
    }

    // Pad shorter version with zeros
    while (version1.size() < version2.size()) version1.push_back(0);
    while (version2.size() < version1.size()) version2.push_back(0);

    // Compare each part
    for (size_t i = 0; i < version1.size(); ++i) {
        if (version1[i] < version2[i]) return -1;
        if (version1[i] > version2[i]) return 1;
    }

    return 0; // Equal
}

VersionInfo checkForNewerRelease(const std::string& current_version) {
    VersionInfo info = {"", false, ""};
    
    CURL *curl;
    CURLcode res;
    std::string readBuffer;
    
    curl = curl_easy_init();
    if(curl) {
        curl_easy_setopt(curl, CURLOPT_URL, "https://api.github.com/repos/raspberrypi/rpi-sb-provisioner/releases/latest");
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, WriteCallback);
        curl_easy_setopt(curl, CURLOPT_WRITEDATA, &readBuffer);
        const std::string userAgent = "rpi-sb-provisioner/" + current_version + " libcurl-agent/1.0";
        curl_easy_setopt(curl, CURLOPT_USERAGENT, userAgent.c_str());
        // This runs before the UI listens. Stations are often offline, or
        // behind a firewall that drops rather than refuses, and libcurl's
        // defaults would then hold start-up for minutes.
        curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 5L);
        curl_easy_setopt(curl, CURLOPT_TIMEOUT, 10L);
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L);
        
        res = curl_easy_perform(curl);
        curl_easy_cleanup(curl);
        
        if(res != CURLE_OK) {
            return info;
        }
        
        std::string tag_name, html_url;
        
        // Extract tag_name using regex
        std::regex tag_regex("\"tag_name\":\\s*\"([^\"]+)\"");
        std::smatch tag_matches;
        if (std::regex_search(readBuffer, tag_matches, tag_regex) && tag_matches.size() > 1) {
            tag_name = tag_matches[1].str();
            // Remove 'v' prefix if present
            if (!tag_name.empty() && tag_name[0] == 'v') {
                tag_name = tag_name.substr(1);
            }
        }
        
        // Extract html_url using regex
        std::regex url_regex("\"html_url\":\\s*\"([^\"]+)\"");
        std::smatch url_matches;
        if (std::regex_search(readBuffer, url_matches, url_regex) && url_matches.size() > 1) {
            html_url = url_matches[1].str();
        }
        
        info.latest = tag_name;
        info.release_url = html_url;
        
        // Compare versions using proper semantic version comparison. A version
        // we cannot parse -- ours or the tag's -- is not evidence of an update,
        // so leave has_newer false and let the UI say nothing.
        if (!tag_name.empty() && !current_version.empty() && tag_name != current_version) {
            const std::optional<int> ordering = compareVersions(current_version, tag_name);
            if (ordering.has_value()) {
                info.has_newer = *ordering < 0;
            }
        }
    }
    
    return info;
}

// Global variables that will be accessed by views
std::string g_packageVersion;
bool g_hasNewerVersion = false;
std::string g_releaseUrl;
std::string g_listenerAddress;
bool g_isPublicBinding = false;

// Print help message
void printHelp(const char* programName) {
    std::cout << "Usage: " << programName << " [OPTIONS]\n\n"
              << "Options:\n"
              << "  -h, --help                 Display this help message and exit\n"
              << "  -v, --version              Display version information and exit\n"
              << "  -a, --address <address>    Set listener address (default: 127.0.0.1)\n"
              << "  -p, --port <port>          Set listener port (default: 3142)\n"
              << "  -s, --https-port <port>    Set HTTPS listener port (default: 3143)\n"
              << "  -d, --disable-https        Disable HTTPS\n"
              << "  -l, --log-level <level>    Set log level (trace, debug, info, warn, error, fatal)\n"
              << "                             Default: trace\n"
              << "  -H, --allowed-host <name>  Accept requests addressed to this host name, such as\n"
              << "                             a reverse proxy's. May be repeated.\n"
              << std::endl;

    std::cout << "Access:\n"
              << "  Operators sign in with their system account, which must be a member of\n"
              << "  the " << provisioner::auth::kOperatorGroup << " group.\n"
              << std::endl;
    
    std::cout << "HTTPS Support:\n"
              << "  By default, the application generates a self-signed certificate\n"
              << "  and sets up an HTTPS listener. The certificate is valid for 1 year\n"
              << "  and is regenerated every time the application starts.\n"
              << std::endl;
}

// Map string to trantor::Logger::LogLevel
trantor::Logger::LogLevel parseLogLevel(const std::string& level) {
    static const std::map<std::string, trantor::Logger::LogLevel> levelMap = {
        {"trace", trantor::Logger::kTrace},
        {"debug", trantor::Logger::kDebug},
        {"info", trantor::Logger::kInfo},
        {"warn", trantor::Logger::kWarn},
        {"error", trantor::Logger::kError},
        {"fatal", trantor::Logger::kFatal}
    };

    std::string levelLower = level;
    std::transform(levelLower.begin(), levelLower.end(), levelLower.begin(), 
                   [](unsigned char c) { return std::tolower(c); });

    auto it = levelMap.find(levelLower);
    if (it != levelMap.end()) {
        return it->second;
    }
    
    std::cerr << "Invalid log level: " << level << std::endl;
    std::cerr << "Valid options are: trace, debug, info, warn, error, fatal" << std::endl;
    return trantor::Logger::kTrace; // Default to trace if invalid
}

// Print version information
void printVersion() {
    std::string version = getPackageVersion();
    std::cout << "Raspberry Pi Secure Boot Provisioner v" << version << std::endl;
}

// Function to generate a self-signed certificate and key
// The names this station answers to, for the certificate's subjectAltName.
static std::string certificateAltNames(const std::string& listenerAddress) {
    std::string names = "DNS:localhost,IP:127.0.0.1,IP:::1";
    char host[256] = {};
    if (gethostname(host, sizeof(host) - 1) == 0 && host[0]) {
        names += std::string(",DNS:") + host + ",DNS:" + host + ".local";
    }
    unsigned char buf[16];
    if (listenerAddress != "0.0.0.0" && listenerAddress != "::" && listenerAddress != "127.0.0.1" &&
        (inet_pton(AF_INET, listenerAddress.c_str(), buf) == 1 || inet_pton(AF_INET6, listenerAddress.c_str(), buf) == 1)) {
        names += ",IP:" + listenerAddress;
    }
    return names;
}

// Keep the certificate a browser was told to trust. One made afresh at every
// start taught operators to click through the warning, which is the habit an
// interception needs, and every copy had serial 1, which Firefox refuses.
static bool certificateStillUsable(const std::string& certPath, const std::string& keyPath) {
    FILE* cf = fopen(certPath.c_str(), "rb");
    if (!cf) return false;
    X509* cert = PEM_read_X509(cf, nullptr, nullptr, nullptr);
    fclose(cf);
    FILE* kf = fopen(keyPath.c_str(), "rb");
    EVP_PKEY* key = kf ? PEM_read_PrivateKey(kf, nullptr, nullptr, nullptr) : nullptr;
    if (kf) fclose(kf);

    bool usable = cert && key && X509_check_private_key(cert, key) == 1;
    if (usable) {
        // At least 30 days left.
        time_t soon = time(nullptr) + 30L * 24 * 3600;
        usable = X509_cmp_time(X509_get0_notAfter(cert), &soon) > 0;
    }
    char host[256] = {};
    if (usable && gethostname(host, sizeof(host) - 1) == 0 && host[0]) {
        usable = X509_check_host(cert, host, 0, 0, nullptr) == 1;
    }
    X509_free(cert);
    EVP_PKEY_free(key);
    return usable;
}

static std::string certificateFingerprint(const std::string& certPath) {
    FILE* cf = fopen(certPath.c_str(), "rb");
    if (!cf) return "";
    X509* cert = PEM_read_X509(cf, nullptr, nullptr, nullptr);
    fclose(cf);
    if (!cert) return "";
    unsigned char md[EVP_MAX_MD_SIZE];
    unsigned int len = 0;
    X509_digest(cert, EVP_sha256(), md, &len);
    X509_free(cert);
    std::string out;
    char byte[4];
    for (unsigned int i = 0; i < len; ++i) {
        snprintf(byte, sizeof(byte), i ? ":%02X" : "%02X", md[i]);
        out += byte;
    }
    return out;
}

bool generateSelfSignedCertificate(const std::string& certPath, const std::string& keyPath,
                                   const std::string& altNames) {
    // Initialize OpenSSL
    OpenSSL_add_all_algorithms();
    ERR_load_crypto_strings();

    // Create RSA key
    EVP_PKEY* pkey = nullptr;
    EVP_PKEY_CTX* ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_RSA, nullptr);
    if (!ctx) {
        std::cerr << "Error creating EVP_PKEY_CTX" << std::endl;
        return false;
    }
    
    if (EVP_PKEY_keygen_init(ctx) <= 0) {
        std::cerr << "Error initializing key generation" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    if (EVP_PKEY_CTX_set_rsa_keygen_bits(ctx, 2048) <= 0) {
        std::cerr << "Error setting RSA key length" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    if (EVP_PKEY_keygen(ctx, &pkey) <= 0) {
        std::cerr << "Error generating RSA key" << std::endl;
        EVP_PKEY_CTX_free(ctx);
        return false;
    }
    
    EVP_PKEY_CTX_free(ctx);

    // Create X509 certificate
    X509* x509 = X509_new();
    if (!x509) {
        std::cerr << "Error creating X509 certificate" << std::endl;
        EVP_PKEY_free(pkey);
        return false;
    }

    // Set certificate details
    // Random, so a replacement is never mistaken for the certificate it replaces.
    {
        unsigned char serial[16];
        if (RAND_bytes(serial, sizeof(serial)) != 1) {
            X509_free(x509);
            EVP_PKEY_free(pkey);
            return false;
        }
        serial[0] &= 0x7f;
        BIGNUM* bn = BN_bin2bn(serial, sizeof(serial), nullptr);
        BN_to_ASN1_INTEGER(bn, X509_get_serialNumber(x509));
        BN_free(bn);
    }
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // Valid for 1 year

    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"UK", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"rpi-sb-provisioner User", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Raspberry Pi Provisioner", -1, -1, 0);
    X509_set_issuer_name(x509, name);

    // Browsers match on subjectAltName only; the CN alone matched nothing.
    {
        X509V3_CTX v3;
        X509V3_set_ctx_nodb(&v3);
        X509V3_set_ctx(&v3, x509, x509, nullptr, nullptr, 0);
        X509_EXTENSION* san = X509V3_EXT_conf_nid(nullptr, &v3, NID_subject_alt_name, altNames.c_str());
        if (!san || !X509_add_ext(x509, san, -1)) {
            std::cerr << "Error adding subjectAltName" << std::endl;
            X509_EXTENSION_free(san);
            X509_free(x509);
            EVP_PKEY_free(pkey);
            return false;
        }
        X509_EXTENSION_free(san);
    }

    // Sign the certificate
    if (!X509_sign(x509, pkey, EVP_sha256())) {
        std::cerr << "Error signing certificate" << std::endl;
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }

    // Save certificate to file
    FILE* certFile = fopen(certPath.c_str(), "wb");
    if (!certFile) {
        std::cerr << "Error opening certificate file for writing" << std::endl;
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    PEM_write_X509(certFile, x509);
    fclose(certFile);

    // Save private key to file
    // Owner-only from creation, whatever the umask.
    const int keyFd = open(keyPath.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
    FILE* keyFile = keyFd >= 0 && fchmod(keyFd, 0600) == 0 ? fdopen(keyFd, "wb") : nullptr;
    if (!keyFile) {
        if (keyFd >= 0) close(keyFd);
        std::cerr << "Error opening key file for writing" << std::endl;
        X509_free(x509);
        EVP_PKEY_free(pkey);
        return false;
    }
    
    PEM_write_PrivateKey(keyFile, pkey, nullptr, nullptr, 0, nullptr, nullptr);
    fclose(keyFile);

    // Clean up
    X509_free(x509);
    EVP_PKEY_free(pkey);
    
    std::cout << "Generated self-signed certificate at " << certPath << std::endl;
    std::cout << "Generated private key at " << keyPath << std::endl;
    
    return true;
}

int main(int argc, char* argv[])
{
    // Initialize libcurl globally
    curl_global_init(CURL_GLOBAL_DEFAULT);
    
    // Default values for listener
    std::string listenerAddress = "127.0.0.1";
    int listenerPort = 3142;
    int httpsPort = 3143; // Default HTTPS port
    bool enableHttps = true; // Enable HTTPS by default
    trantor::Logger::LogLevel logLevel = trantor::Logger::kTrace;
    std::vector<std::string> allowedHosts;

    // Parse command line options
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"address", required_argument, 0, 'a'},
        {"port", required_argument, 0, 'p'},
        {"https-port", required_argument, 0, 's'},
        {"disable-https", no_argument, 0, 'd'},
        {"log-level", required_argument, 0, 'l'},
        {"allowed-host", required_argument, 0, 'H'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hva:p:s:dl:H:", long_options, nullptr)) != -1) {
        switch (opt) {
            case 'h':
                printHelp(argv[0]);
                return 0;
            case 'v':
                printVersion();
                return 0;
            case 'a':
                listenerAddress = optarg;
                break;
            case 'p':
                try {
                    listenerPort = std::stoi(optarg);
                    if (listenerPort <= 0 || listenerPort > 65535) {
                        std::cerr << "Port must be between 1 and 65535" << std::endl;
                        return 1;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Invalid port number: " << optarg << std::endl;
                    return 1;
                }
                break;
            case 's':
                try {
                    httpsPort = std::stoi(optarg);
                    if (httpsPort <= 0 || httpsPort > 65535) {
                        std::cerr << "HTTPS port must be between 1 and 65535" << std::endl;
                        return 1;
                    }
                } catch (const std::exception& e) {
                    std::cerr << "Invalid HTTPS port number: " << optarg << std::endl;
                    return 1;
                }
                break;
            case 'd':
                enableHttps = false;
                break;
            case 'l':
                logLevel = parseLogLevel(optarg);
                break;
            case 'H':
                allowedHosts.emplace_back(optarg);
                break;
            default:
                printHelp(argv[0]);
                return 1;
        }
    }

    // Private runtime directory, root-only: temporary PIN files and the TLS
    // key live here. The key used to be written under /tmp, where any local
    // user could read it, or plant a symlink for root to write through.
    constexpr const char* pinTempDir = "/run/rpi-sb-provisioner";
    try {
        std::filesystem::create_directories(pinTempDir);
        // Set directory permissions to 0700 (owner only)
        chmod(pinTempDir, S_IRWXU);
        LOG_INFO << "Created secure PIN temp directory: " << pinTempDir;
    } catch (const std::filesystem::filesystem_error& e) {
        // Non-fatal - will fall back to /tmp with per-file permissions
        LOG_WARN << "Could not create secure PIN temp directory " << pinTempDir 
                 << ": " << e.what() << " (will use fallback)";
    }
    // Kept across restarts, so a certificate an operator has accepted stays
    // the one they accepted.
    const std::string certDir = "/var/lib/rpi-sb-provisioner/tls";
    std::error_code certDirError;
    std::filesystem::create_directories(certDir, certDirError);
    chmod(certDir.c_str(), S_IRWXU);

    // Generate self-signed certificate paths
    std::string certPath = certDir + "/cert.pem";
    std::string keyPath = certDir + "/key.pem";

    // Reuse the certificate if it is still good, else make a new one
    bool certGenerated = false;
    if (enableHttps) {
        certGenerated = certificateStillUsable(certPath, keyPath) ||
                        generateSelfSignedCertificate(certPath, keyPath, certificateAltNames(listenerAddress));
        if (certGenerated) {
            LOG_INFO << "HTTPS certificate SHA-256 fingerprint: " << certificateFingerprint(certPath);
        } else {
            std::cerr << "Failed to generate self-signed certificate. HTTPS will be disabled." << std::endl;
            enableHttps = false;
        }
    }

    auto nthreads = std::thread::hardware_concurrency();
    if (nthreads == 0) nthreads = 1;

    provisioner::Images imageHandlers = {};
    provisioner::Devices deviceHandlers = {};
    provisioner::Customisation customisationHandlers = {};
    provisioner::Options optionHandlers = {};
    provisioner::Services serviceHandlers = {};
    provisioner::Manufacturing manufacturingHandlers = {};
    provisioner::ScanTool scanToolHandlers = {};
    provisioner::AuditLog auditLogHandlers = {}; // Audit logging for security monitoring

    auto& app = HttpAppFramework::instance();

    // Get package version and set it as a global value
    g_packageVersion = getPackageVersion();
    
    // Check for newer GitHub releases
    VersionInfo versionInfo = checkForNewerRelease(g_packageVersion);
    g_hasNewerVersion = versionInfo.has_newer;
    g_releaseUrl = versionInfo.release_url;
    
    // Report at startup whether this host can encrypt secrets at rest, so an
    // unusable station says so in the journal on boot rather than at the moment
    // an operator first tries to save a key. Not fatal: a host with no device
    // key still provisions with an already-configured key, and the paths that
    // need one refuse individually.
    {
        const auto deviceKey = provisioner::keywrap::deviceKeyStatus();
        if (deviceKey.state == provisioner::keywrap::DeviceKeyState::Ok) {
            LOG_INFO << "Device key present (OTP slot " << deviceKey.keyId
                     << "); secrets will be encrypted at rest";
        } else {
            LOG_WARN << "No usable device key (" << provisioner::keywrap::stateName(deviceKey.state)
                     << "): " << deviceKey.reason;
            if (!deviceKey.remedy.empty()) LOG_WARN << "Remedy: " << deviceKey.remedy;
            LOG_WARN << "Storing signing keys or HSM PINs will be refused until this is resolved";
        }
    }

    // Set listener address for security warning in UI
    g_listenerAddress = listenerAddress;
    // Check if binding to a non-localhost address (potential security risk)
    g_isPublicBinding = (listenerAddress != "127.0.0.1" && 
                         listenerAddress != "localhost" && 
                         listenerAddress != "::1");

    // Every request passes the sign-in gate first. There are deliberately no
    // CORS headers: no other origin has any business reading these responses.
    provisioner::auth::install(app, provisioner::auth::Config{
        listenerAddress, allowedHosts, g_isPublicBinding});

    imageHandlers.registerHandlers(app);
    deviceHandlers.registerHandlers(app);
    customisationHandlers.registerHandlers(app);
    optionHandlers.registerHandlers(app);
    serviceHandlers.registerHandlers(app);
    manufacturingHandlers.registerHandlers(app);
    scanToolHandlers.registerHandlers(app);
    auditLogHandlers.registerHandlers(app);

    // Register root path handler to redirect to devices
    app.registerHandler("/", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k302Found);
        resp->addHeader("Location", "/devices");
        callback(resp);
    });

    // Configure upload path
    constexpr const char *uploadPath = "/srv/rpi-sb-provisioner/uploads";

    // Create directory if it doesn't exist
    std::filesystem::create_directories(uploadPath);

    // Configure static files path (document root, static files served from /static/ subfolder)
    constexpr const char *staticPath = "/usr/share/rpi-sb-provisioner";
    
    // Configure Drogon app framework
    app
    .setBeforeListenSockOptCallback([](int fd) {
        LOG_INFO << "setBeforeListenSockOptCallback:" << fd;

        int enable = 1;
        if (setsockopt(
                fd, IPPROTO_TCP, TCP_FASTOPEN, &enable, sizeof(enable)) ==
            -1)
        {
            LOG_INFO << "setsockopt TCP_FASTOPEN failed";
        }
    })
    .setLogLevel(logLevel)
    .addListener(listenerAddress, listenerPort) // HTTP listener
    .setClientMaxBodySize(std::numeric_limits<size_t>::max())
    .enableRequestStream()
    .setThreadNum(nthreads)
    .setUploadPath(uploadPath)
    .setDocumentRoot(staticPath);  // Set static files path
    
    // Add HTTPS listener if enabled
    if (enableHttps && certGenerated) {
        app.setSSLFiles(certPath, keyPath)
           .addListener(listenerAddress, httpsPort, true); // true for HTTPS
        LOG_INFO << "HTTPS listener enabled on " << listenerAddress << ":" << httpsPort;
    }
    
    // Drogon's own 404 page declares no language, so screen readers guess.
    {
        auto notFound = HttpResponse::newHttpResponse();
        notFound->setContentTypeCode(CT_TEXT_HTML);
        notFound->setBody(
            "<!DOCTYPE html>\n<html lang=\"en\">\n<head><meta charset=\"utf-8\">"
            "<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">"
            "<title>404: Page not found</title></head>\n"
            "<body style=\"font-family: sans-serif; margin: 2rem; color: #212529;\"><main>"
            "<h1>Page not found</h1><p>There is nothing at this address.</p>"
            "<p><a href=\"/devices\">Go to the devices page</a></p></main></body>\n</html>\n");
        app.setCustom404Page(notFound);
    }

    // Run the application
    app.run();
    
    // Clean up curl global resources
    curl_global_cleanup();
    
    return 0;
}