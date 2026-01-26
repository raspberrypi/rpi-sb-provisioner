#include "utils.h"
#include <fstream>
#include <filesystem>
#include <algorithm>
#include <regex>
#include <functional>
#include <drogon/drogon.h>
#include "include/audit.h"

namespace provisioner {
    namespace utils {
        
        constexpr const char* CONFIG_FILE_PATH = "/etc/rpi-sb-provisioner/config";
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
            std::ifstream configFile(CONFIG_FILE_PATH);
            std::string line;
            
            if (!configFile.is_open()) {
                LOG_ERROR << "Failed to open config file: " << CONFIG_FILE_PATH;
                
                if (logAccessToAudit) {
                    AuditLog::logFileSystemAccess("READ", CONFIG_FILE_PATH, false);
                }
                
                return std::nullopt;
            }
            
            if (logAccessToAudit) {
                AuditLog::logFileSystemAccess("READ", CONFIG_FILE_PATH, true);
            }
            
            while (std::getline(configFile, line)) {
                // Skip commented lines
                if (!line.empty() && line[0] == '#') {
                    continue;
                }
                
                size_t delimiter_pos = line.find('=');
                if (delimiter_pos != std::string::npos) {
                    std::string current_key = line.substr(0, delimiter_pos);
                    if (current_key == key) {
                        std::string value = line.substr(delimiter_pos + 1);
                        configFile.close();
                        return value;
                    }
                }
            }
            
            configFile.close();
            return std::nullopt;
        }
        
        std::map<std::string, std::string> getAllConfigValues(bool logAccessToAudit) {
            std::map<std::string, std::string> configValues;
            std::ifstream configFile(CONFIG_FILE_PATH);
            std::string line;
            
            if (!configFile.is_open()) {
                LOG_ERROR << "Failed to open config file: " << CONFIG_FILE_PATH;
                
                if (logAccessToAudit) {
                    AuditLog::logFileSystemAccess("READ", CONFIG_FILE_PATH, false);
                }
                
                return configValues;
            }
            
            if (logAccessToAudit) {
                AuditLog::logFileSystemAccess("READ", CONFIG_FILE_PATH, true);
            }
            
            while (std::getline(configFile, line)) {
                // Skip commented lines
                if (!line.empty() && line[0] == '#') {
                    continue;
                }
                
                size_t delimiter_pos = line.find('=');
                if (delimiter_pos != std::string::npos) {
                    std::string key = line.substr(0, delimiter_pos);
                    std::string value = line.substr(delimiter_pos + 1);
                    configValues[key] = value;
                }
            }
            
            configFile.close();
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