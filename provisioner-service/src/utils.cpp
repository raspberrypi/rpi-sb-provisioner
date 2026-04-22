#include "utils.h"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <regex>
#include <functional>
#include <cstdio>
#include <cstring>
#include <cstdlib>
#include <sys/wait.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <drogon/drogon.h>
#include "include/audit.h"

namespace provisioner {
    namespace utils {
        
        // Private directory for temporary PIN files (more secure than /tmp)
        // This directory should be created with mode 0700 at service startup
        constexpr const char* PIN_TEMP_DIR = "/run/rpi-sb-provisioner";
        
        // RAII wrapper for secure temporary PIN files
        // Guarantees cleanup even on exceptions, and securely overwrites before deletion
        class SecureTempPinFile {
        public:
            SecureTempPinFile() = default;
            
            ~SecureTempPinFile() {
                cleanup();
            }
            
            // Non-copyable
            SecureTempPinFile(const SecureTempPinFile&) = delete;
            SecureTempPinFile& operator=(const SecureTempPinFile&) = delete;
            
            // Movable
            SecureTempPinFile(SecureTempPinFile&& other) noexcept : path_(std::move(other.path_)) {
                other.path_.clear();
            }
            
            SecureTempPinFile& operator=(SecureTempPinFile&& other) noexcept {
                if (this != &other) {
                    cleanup();
                    path_ = std::move(other.path_);
                    other.path_.clear();
                }
                return *this;
            }
            
            // Create a secure temporary file and write the PIN to it
            // Returns true on success, false on failure
            bool create(const std::string& pin) {
                cleanup();  // Clean up any existing file
                
                // Ensure the private directory exists with secure permissions
                ensurePrivateDirectory();
                
                // Use mkstemp for atomic secure file creation
                // mkstemp creates with mode 0600 by default
                std::string templatePath = std::string(PIN_TEMP_DIR) + "/pin-XXXXXX";
                std::vector<char> pathBuf(templatePath.begin(), templatePath.end());
                pathBuf.push_back('\0');
                
                // Set umask to ensure restrictive permissions
                mode_t oldUmask = umask(0077);
                int fd = mkstemp(pathBuf.data());
                umask(oldUmask);
                
                if (fd < 0) {
                    // Fall back to /tmp if private directory fails
                    templatePath = "/tmp/rpi-pin-XXXXXX";
                    pathBuf.assign(templatePath.begin(), templatePath.end());
                    pathBuf.push_back('\0');
                    
                    oldUmask = umask(0077);
                    fd = mkstemp(pathBuf.data());
                    umask(oldUmask);
                    
                    if (fd < 0) {
                        LOG_ERROR << "Failed to create secure temp file for PIN";
                        return false;
                    }
                }
                
                path_ = pathBuf.data();
                
                // Tighten permissions to read-only (0400)
                if (fchmod(fd, S_IRUSR) < 0) {
                    LOG_WARN << "Failed to set temp PIN file to read-only";
                }
                
                // Write the PIN
                ssize_t written = write(fd, pin.c_str(), pin.length());
                close(fd);
                
                if (written != static_cast<ssize_t>(pin.length())) {
                    LOG_ERROR << "Failed to write PIN to temp file";
                    cleanup();
                    return false;
                }
                
                return true;
            }
            
            const std::string& path() const { return path_; }
            bool valid() const { return !path_.empty(); }
            
        private:
            std::string path_;
            
            void cleanup() {
                if (path_.empty()) return;
                
                // Securely overwrite the file contents before deletion
                int fd = open(path_.c_str(), O_WRONLY);
                if (fd >= 0) {
                    // Overwrite with zeros
                    char zeros[256];
                    std::memset(zeros, 0, sizeof(zeros));
                    write(fd, zeros, sizeof(zeros));
                    fsync(fd);
                    close(fd);
                }
                
                // Delete the file
                std::filesystem::remove(path_);
                path_.clear();
            }
            
            static void ensurePrivateDirectory() {
                if (!std::filesystem::exists(PIN_TEMP_DIR)) {
                    try {
                        std::filesystem::create_directories(PIN_TEMP_DIR);
                        // Set directory permissions to 0700 (owner only)
                        chmod(PIN_TEMP_DIR, S_IRWXU);
                    } catch (const std::filesystem::filesystem_error& e) {
                        LOG_WARN << "Could not create private PIN directory: " << e.what();
                        // Will fall back to /tmp
                    }
                }
            }
        };
        
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
            // Helper to run a command and capture output
            std::pair<int, std::string> runCommand(const std::string& cmd) {
                std::string output;
                FILE* pipe = popen(cmd.c_str(), "r");
                if (!pipe) {
                    return {-1, "Failed to run command"};
                }
                
                char buffer[256];
                while (fgets(buffer, sizeof(buffer), pipe) != nullptr) {
                    output += buffer;
                }
                
                int exitCode = pclose(pipe);
                return {WEXITSTATUS(exitCode), output};
            }
            
            // Parse OpenSSL text output for key info
            KeyInfo parseOpenSSLOutput(const std::string& output, bool isPkcs11 = false) {
                KeyInfo info;
                info.success = true;
                info.isPrivateKey = true;  // We're always checking private keys
                
                // Check for RSA key
                if (output.find("RSA Private-Key") != std::string::npos || 
                    output.find("Private-Key:") != std::string::npos) {
                    info.algorithm = "RSA";
                    
                    // Extract key size - look for patterns like "(2048 bit)" or "(2048 bit, 2 primes)"
                    std::regex sizeRegex(R"(\((\d+)\s*bit)");
                    std::smatch match;
                    if (std::regex_search(output, match, sizeRegex)) {
                        info.keySize = std::stoi(match[1].str());
                    }
                } else if (output.find("EC Private-Key") != std::string::npos) {
                    info.algorithm = "EC";
                    
                    // Extract curve size
                    std::regex sizeRegex(R"(\((\d+)\s*bit)");
                    std::smatch match;
                    if (std::regex_search(output, match, sizeRegex)) {
                        info.keySize = std::stoi(match[1].str());
                    }
                } else if (output.find("DSA Private-Key") != std::string::npos) {
                    info.algorithm = "DSA";
                    
                    std::regex sizeRegex(R"(\((\d+)\s*bit)");
                    std::smatch match;
                    if (std::regex_search(output, match, sizeRegex)) {
                        info.keySize = std::stoi(match[1].str());
                    }
                } else {
                    info.algorithm = "Unknown";
                    info.keySize = 0;
                }
                
                // Determine fitness for purpose (Pi secure boot requires RSA-2048)
                if (info.algorithm == "RSA" && info.keySize == 2048) {
                    info.isFitForPurpose = true;
                    info.statusLevel = "valid";
                    info.statusMessage = "Valid for secure boot";
                } else if (info.algorithm == "RSA" && info.keySize > 0) {
                    info.isFitForPurpose = false;
                    info.statusLevel = "warning";
                    info.statusMessage = "RSA-2048 recommended for Pi secure boot";
                } else if (info.algorithm != "RSA") {
                    info.isFitForPurpose = false;
                    info.statusLevel = "error";
                    info.statusMessage = "Unsupported: Pi secure boot requires RSA";
                } else {
                    info.isFitForPurpose = false;
                    info.statusLevel = "error";
                    info.statusMessage = "Could not determine key type";
                }
                
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
            
            // Use OpenSSL to parse the key and get info
            // Try RSA first
            std::string cmd = "openssl rsa -in \"" + path + "\" -text -noout 2>&1";
            auto [exitCode, output] = runCommand(cmd);
            
            if (exitCode == 0) {
                info = parseOpenSSLOutput(output);
                
                // Get fingerprint of public key
                std::string fpCmd = "openssl rsa -in \"" + path + "\" -pubout 2>/dev/null | openssl sha256 -r 2>/dev/null";
                auto [fpExit, fpOutput] = runCommand(fpCmd);
                if (fpExit == 0 && !fpOutput.empty()) {
                    // Output format: "abc123... *stdin"
                    size_t spacePos = fpOutput.find(' ');
                    if (spacePos != std::string::npos) {
                        info.fingerprint = fpOutput.substr(0, spacePos);
                    } else {
                        // Trim newline
                        info.fingerprint = fpOutput;
                        while (!info.fingerprint.empty() && 
                               (info.fingerprint.back() == '\n' || info.fingerprint.back() == '\r')) {
                            info.fingerprint.pop_back();
                        }
                    }
                }
                
                LOG_INFO << "Parsed PEM key: " << info.algorithm << "-" << info.keySize 
                         << " (" << info.statusLevel << ")";
                return info;
            }
            
            // Try EC key
            cmd = "openssl ec -in \"" + path + "\" -text -noout 2>&1";
            std::tie(exitCode, output) = runCommand(cmd);
            
            if (exitCode == 0) {
                info = parseOpenSSLOutput(output);
                LOG_INFO << "Parsed EC key: " << info.algorithm << "-" << info.keySize 
                         << " (" << info.statusLevel << ")";
                return info;
            }
            
            // Try generic pkey
            cmd = "openssl pkey -in \"" + path + "\" -text -noout 2>&1";
            std::tie(exitCode, output) = runCommand(cmd);
            
            if (exitCode == 0) {
                info = parseOpenSSLOutput(output);
                LOG_INFO << "Parsed key: " << info.algorithm << "-" << info.keySize 
                         << " (" << info.statusLevel << ")";
                return info;
            }
            
            // Failed to parse
            info.success = false;
            info.errorMessage = "Failed to parse key file: " + output;
            info.statusLevel = "error";
            info.statusMessage = "Invalid key format";
            LOG_WARN << "Failed to parse key file: " << path << " - " << output;
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
            
            // RAII wrapper ensures temp PIN files are always cleaned up securely,
            // even if an exception is thrown
            SecureTempPinFile tempPinFile;
            SecureTempPinFile tempPinFileFp;  // For fingerprint command
            
            // Build the effective URI with PIN handling
            std::string effectiveUri = uri;
            
            // If a PIN is provided directly (for validation), create a secure temporary file
            if (!pin.empty()) {
                if (!tempPinFile.create(pin)) {
                    info.success = false;
                    info.errorMessage = "Failed to create secure temp file for PIN";
                    info.statusLevel = "error";
                    info.statusMessage = "Internal error";
                    return info;
                }
                
                // Append pin-source to URI (use ? if no query params, & if there are)
                if (effectiveUri.find('?') != std::string::npos) {
                    effectiveUri += "&pin-source=" + tempPinFile.path();
                } else {
                    effectiveUri += "?pin-source=" + tempPinFile.path();
                }
            } else if (isPkcs11PinConfigured()) {
                // Use stored PIN file
                effectiveUri = buildPkcs11UriWithPinSource(uri);
            }
            
            // Use OpenSSL with PKCS#11 engine to query the key
            // Note: This requires the HSM to be connected and accessible
            std::string cmd = "openssl rsa -engine pkcs11 -inform engine -in \"" + effectiveUri + "\" -text -noout 2>&1";
            auto [exitCode, output] = runCommand(cmd);
            
            // Note: tempPinFile is cleaned up automatically by RAII destructor
            
            if (exitCode == 0) {
                info = parseOpenSSLOutput(output, true);
                
                // Get fingerprint of public key from PKCS#11
                std::string fpUri = uri;
                if (!pin.empty()) {
                    // Create a new secure temp file for fingerprint command
                    if (tempPinFileFp.create(pin)) {
                        if (fpUri.find('?') != std::string::npos) {
                            fpUri += "&pin-source=" + tempPinFileFp.path();
                        } else {
                            fpUri += "?pin-source=" + tempPinFileFp.path();
                        }
                    }
                } else if (isPkcs11PinConfigured()) {
                    fpUri = buildPkcs11UriWithPinSource(uri);
                }
                
                std::string fpCmd = "openssl rsa -engine pkcs11 -inform engine -in \"" + fpUri + 
                                   "\" -pubout 2>/dev/null | openssl sha256 -r 2>/dev/null";
                auto [fpExit, fpOutput] = runCommand(fpCmd);
                
                // Note: tempPinFileFp is cleaned up automatically by RAII destructor
                
                if (fpExit == 0 && !fpOutput.empty()) {
                    size_t spacePos = fpOutput.find(' ');
                    if (spacePos != std::string::npos) {
                        info.fingerprint = fpOutput.substr(0, spacePos);
                    } else {
                        info.fingerprint = fpOutput;
                        while (!info.fingerprint.empty() && 
                               (info.fingerprint.back() == '\n' || info.fingerprint.back() == '\r')) {
                            info.fingerprint.pop_back();
                        }
                    }
                }
                
                LOG_INFO << "Parsed PKCS#11 key: " << info.algorithm << "-" << info.keySize 
                         << " (" << info.statusLevel << ")";
                return info;
            }
            
            // Check for common PKCS#11 errors
            // SECURITY: Do not log raw OpenSSL output - it may contain sensitive HSM information
            if (output.find("engine") != std::string::npos && output.find("not found") != std::string::npos) {
                info.success = false;
                info.errorMessage = "PKCS#11 engine not available";
                info.statusLevel = "error";
                info.statusMessage = "PKCS#11 engine not installed";
            } else if (output.find("login") != std::string::npos || output.find("PIN") != std::string::npos ||
                       output.find("pin") != std::string::npos || output.find("authenticate") != std::string::npos) {
                info.success = false;
                info.errorMessage = "PIN incorrect or not provided";
                info.statusLevel = "error";
                info.statusMessage = "Invalid PIN";
            } else if (output.find("token") != std::string::npos || output.find("slot") != std::string::npos) {
                info.success = false;
                info.errorMessage = "Cannot access HSM - check connection";
                info.statusLevel = "error";
                info.statusMessage = "Cannot access HSM";
            } else if (output.find("object") != std::string::npos || output.find("key") != std::string::npos) {
                info.success = false;
                info.errorMessage = "Key not found on HSM";
                info.statusLevel = "error";
                info.statusMessage = "Key not found on HSM";
            } else {
                info.success = false;
                info.errorMessage = "Failed to access PKCS#11 key";
                info.statusLevel = "error";
                info.statusMessage = "Cannot access HSM - check connection";
            }
            
            // SECURITY: Only log the error type, not the raw OpenSSL output which may contain
            // sensitive information about the HSM configuration or authentication state
            LOG_WARN << "Failed to parse PKCS#11 key: " << info.statusMessage;
            return info;
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
            
            // Write the PIN to the file
            std::ofstream pinFile(PKCS11_PIN_FILE);
            if (!pinFile.is_open()) {
                LOG_ERROR << "Failed to open PIN file for writing: " << PKCS11_PIN_FILE;
                return false;
            }
            
            // Write PIN without newline (as per PKCS#11 URI spec)
            pinFile << pin;
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
        
        std::string buildPkcs11UriWithPinSource(const std::string& baseUri) {
            if (!isPkcs11PinConfigured()) {
                return baseUri;
            }
            
            // Append pin-source to URI
            // Use ? if no query params exist, & if there are already query params
            if (baseUri.find('?') != std::string::npos) {
                return baseUri + "&pin-source=" + PKCS11_PIN_FILE;
            } else {
                return baseUri + "?pin-source=" + PKCS11_PIN_FILE;
            }
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