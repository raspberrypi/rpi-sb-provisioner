#pragma once

#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>
#include <string>
#include <regex>
#include <optional>
#include <map>

namespace provisioner {
    namespace utils {
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