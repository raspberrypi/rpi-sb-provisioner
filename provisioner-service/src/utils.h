#pragma once

#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <string>
#include <regex>
#include <optional>
#include <map>
#include <vector>
#include <random>
#include <mutex>
#include <chrono>
#include <unordered_map>

namespace provisioner {
    namespace utils {
        
        // ===== Configuration Paths =====
        // Package defaults are read first, then user config overrides
        constexpr const char* CONFIG_DEFAULTS_PATH = "/usr/share/rpi-sb-provisioner/defaults/config";
        constexpr const char* CONFIG_USER_PATH = "/etc/rpi-sb-provisioner/config";
        
        // ===== Firmware Information =====
        
        /**
         * Information about a firmware file
         */
        struct FirmwareInfo {
            std::string version;        // e.g., "2024-01-15"
            std::string filename;       // e.g., "pieeprom-2024-01-15.bin"
            std::string filepath;       // Full path to file
            std::string releaseChannel; // e.g., "default", "latest", "beta"
            uintmax_t size;             // File size in bytes
        };
        
        /**
         * Scan the firmware directory for available firmware versions
         * 
         * @param deviceFamily The device family ("4", "5", or "2W")
         * @return A vector of FirmwareInfo sorted by version (newest first)
         */
        std::vector<FirmwareInfo> scanFirmwareDirectory(const std::string& deviceFamily);
        
        /**
         * Get the chip number for a device family
         * 
         * @param deviceFamily The device family ("4", "5", or "2W")
         * @return The chip number ("2711", "2712") or empty string if unknown
         */
        inline std::string getChipNumberForFamily(const std::string& deviceFamily) {
            if (deviceFamily == "4") return "2711";
            if (deviceFamily == "5") return "2712";
            return "";
        }
        
        // ===== CSRF Protection =====
        
        /**
         * CSRF token manager - handles generation and validation of tokens
         * Tokens are time-limited and single-use for maximum security
         */
        class CsrfTokenManager {
        public:
            static CsrfTokenManager& getInstance();
            
            /**
             * Generate a new CSRF token for a session
             * 
             * @param sessionId A unique identifier for the session (can be IP + User-Agent hash)
             * @return The generated token
             */
            std::string generateToken(const std::string& sessionId);
            
            /**
             * Validate a CSRF token
             * 
             * @param sessionId The session identifier
             * @param token The token to validate
             * @return true if valid, false otherwise
             */
            bool validateToken(const std::string& sessionId, const std::string& token);
            
            /**
             * Clean up expired tokens (call periodically)
             */
            void cleanupExpiredTokens();
            
        private:
            CsrfTokenManager() = default;
            
            struct TokenInfo {
                std::string token;
                std::chrono::steady_clock::time_point createdAt;
                bool used = false;
            };
            
            std::mutex mutex_;
            std::unordered_map<std::string, std::vector<TokenInfo>> sessionTokens_;
            
            static constexpr int TOKEN_VALIDITY_SECONDS = 3600;  // 1 hour
            static constexpr int MAX_TOKENS_PER_SESSION = 10;
            static constexpr int TOKEN_LENGTH = 32;
        };
        
        /**
         * Generate a session ID from request (IP + User-Agent hash)
         * 
         * @param req The HTTP request
         * @return A session identifier string
         */
        std::string getSessionIdFromRequest(const drogon::HttpRequestPtr& req);
        
        /**
         * Validate CSRF token from request header or body
         * 
         * @param req The HTTP request
         * @return true if valid, false otherwise
         */
        bool validateCsrfToken(const drogon::HttpRequestPtr& req);
        /**
         * Sanitize path components to prevent directory traversal attacks
         * 
         * @param input The path component string to sanitize
         * @return A sanitized string containing only safe characters
         */
        inline std::string sanitize_path_component(const std::string& input) {
            // Only allow alphanumeric characters and some safe symbols
            // Remove or replace any characters that could be used for path traversal
            std::regex unsafe_chars("[^a-zA-Z0-9_\\-]");
            return std::regex_replace(input, unsafe_chars, "_");
        }

        /**
         * Create a consistent error response that handles both HTML and JSON formats
         * 
         * @param req The original HTTP request
         * @param errorMessage The main error message to display
         * @param statusCode The HTTP status code to return
         * @param errorTitle Optional title for the error page
         * @param errorCode Optional error code identifier
         * @param errorDetails Optional technical details for debugging
         * @return HttpResponsePtr The properly formatted response
         */
        inline drogon::HttpResponsePtr createErrorResponse(
            const drogon::HttpRequestPtr& req,
            const std::string& errorMessage,
            drogon::HttpStatusCode statusCode = drogon::k500InternalServerError,
            const std::string& errorTitle = "",
            const std::string& errorCode = "",
            const std::string& errorDetails = "")
        {
            // Check if client accepts HTML
            auto acceptHeader = req->getHeader("Accept");
            if (!acceptHeader.empty() && acceptHeader.find("text/html") != std::string::npos) {
                // Return HTML error page
                drogon::HttpViewData viewData;
                viewData.insert("currentPage", std::string("")); // No active page in navbar
                viewData.insert("error_message", errorMessage);
                
                if (!errorTitle.empty()) {
                    viewData.insert("error_title", errorTitle);
                }
                
                if (!errorCode.empty()) {
                    viewData.insert("error_code", errorCode);
                }
                
                if (!errorDetails.empty()) {
                    viewData.insert("error_details", errorDetails);
                }
                
                auto resp = drogon::HttpResponse::newHttpViewResponse("error.csp", viewData);
                resp->setStatusCode(statusCode);
                return resp;
            } else {
                // Return JSON error
                Json::Value error;
                error["error"] = errorMessage;
                
                if (!errorCode.empty()) {
                    error["error_code"] = errorCode;
                }
                
                if (!errorDetails.empty()) {
                    error["details"] = errorDetails;
                }
                
                auto resp = drogon::HttpResponse::newHttpJsonResponse(error);
                resp->setStatusCode(statusCode);
                return resp;
            }
        }

        /**
         * Read a single configuration value from the config file
         * 
         * @param key The configuration key to look for
         * @param logAccessToAudit Whether to log file access to the audit log
         * @return An optional string containing the value if found
         */
        std::optional<std::string> getConfigValue(const std::string& key, bool logAccessToAudit = true);
        
        /**
         * Read all configuration values from the config file
         * 
         * @param logAccessToAudit Whether to log file access to the audit log
         * @return A map of all key-value pairs in the config file
         */
        std::map<std::string, std::string> getAllConfigValues(bool logAccessToAudit = true);
        
        /**
         * Create an appropriate error response for configuration file read errors
         * 
         * @param req The original HTTP request
         * @param configKey The configuration key that was being searched for (optional)
         * @return HttpResponsePtr The error response
         */
        drogon::HttpResponsePtr createConfigErrorResponse(
            const drogon::HttpRequestPtr& req,
            const std::string& configKey = "");
    } // namespace utils
} // namespace provisioner 