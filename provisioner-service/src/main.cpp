#include <drogon/drogon.h>
#include <netinet/tcp.h>
#include <filesystem>
#include <cstdio>
#include <memory>
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
#include <fstream>

#include "images.h"
#include "devices.h"
#include "customisation.h"
#include "options.h"
#include <services.h>
#include "manufacturing.h"
#include "include/scantool.h"
#include "include/audit.h"

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
        curl_easy_setopt(curl, CURLOPT_USERAGENT, "rpi-sb-provisioner/" + current_version + " libcurl-agent/1.0");
        
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
        
        // Compare versions (simple string comparison - assuming versions are in compatible format)
        if (!tag_name.empty() && !current_version.empty() && tag_name != current_version) {
            info.has_newer = tag_name > current_version;
        }
    }
    
    return info;
}

// Global variables that will be accessed by views
std::string g_packageVersion;
bool g_hasNewerVersion = false;
std::string g_releaseUrl;

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
bool generateSelfSignedCertificate(const std::string& certPath, const std::string& keyPath) {
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
    ASN1_INTEGER_set(X509_get_serialNumber(x509), 1);
    X509_gmtime_adj(X509_get_notBefore(x509), 0);
    X509_gmtime_adj(X509_get_notAfter(x509), 31536000L); // Valid for 1 year

    X509_set_pubkey(x509, pkey);

    X509_NAME* name = X509_get_subject_name(x509);
    X509_NAME_add_entry_by_txt(name, "C", MBSTRING_ASC, (unsigned char*)"UK", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "O", MBSTRING_ASC, (unsigned char*)"rpi-sb-provisioner User", -1, -1, 0);
    X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, (unsigned char*)"Raspberry Pi Provisioner", -1, -1, 0);
    X509_set_issuer_name(x509, name);

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
    FILE* keyFile = fopen(keyPath.c_str(), "wb");
    if (!keyFile) {
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

    // Parse command line options
    static struct option long_options[] = {
        {"help", no_argument, 0, 'h'},
        {"version", no_argument, 0, 'v'},
        {"address", required_argument, 0, 'a'},
        {"port", required_argument, 0, 'p'},
        {"https-port", required_argument, 0, 's'},
        {"disable-https", no_argument, 0, 'd'},
        {"log-level", required_argument, 0, 'l'},
        {0, 0, 0, 0}
    };

    int opt;
    while ((opt = getopt_long(argc, argv, "hva:p:s:dl:", long_options, nullptr)) != -1) {
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
            default:
                printHelp(argv[0]);
                return 1;
        }
    }

    // Create the certificates directory if it doesn't exist
    std::string certDir = "/tmp/rpi-sb-provisioner";
    std::filesystem::create_directories(certDir);
    
    // Generate self-signed certificate paths
    std::string certPath = certDir + "/cert.pem";
    std::string keyPath = certDir + "/key.pem";

    // Generate the self-signed certificate
    bool certGenerated = false;
    if (enableHttps) {
        certGenerated = generateSelfSignedCertificate(certPath, keyPath);
        if (!certGenerated) {
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

    // Configure static files path
    constexpr const char *staticPath = "/usr/share/rpi-sb-provisioner/static";
    
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
    .setThreadNum(nthreads)
    .setUploadPath(uploadPath)
    .setDocumentRoot(staticPath);  // Set static files path
    
    // Add HTTPS listener if enabled
    if (enableHttps && certGenerated) {
        app.setSSLFiles(certPath, keyPath)
           .addListener(listenerAddress, httpsPort, true); // true for HTTPS
        LOG_INFO << "HTTPS listener enabled on " << listenerAddress << ":" << httpsPort;
    }
    
    // Run the application
    app.run();
    
    // Clean up curl global resources
    curl_global_cleanup();
    
    // Clean up the certificate files
    if (certGenerated) {
        std::remove(certPath.c_str());
        std::remove(keyPath.c_str());
    }
    
    return 0;
}