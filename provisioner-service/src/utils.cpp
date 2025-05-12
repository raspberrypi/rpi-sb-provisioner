#include "utils.h"
#include <fstream>
#include <drogon/drogon.h>
#include "include/audit.h"

namespace provisioner {
    namespace utils {
        
        constexpr const char* CONFIG_FILE_PATH = "/etc/rpi-sb-provisioner/config";
        
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