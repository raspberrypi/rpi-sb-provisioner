#include <string_view>
#include <fstream>
#include <filesystem>
#include <sstream>
#include <regex>
#include <set>
#include <algorithm>

#include "include/options.h"
#include <drogon/HttpAppFramework.h>
#include "utils.h"
#include "include/audit.h"

namespace provisioner {
    namespace {
        const std::string OPTIONS_PATH = "/options";

        // Function to remove contents of a directory
        void removeDirectoryContents(const std::string& dirPath) {
            try {
                for (const auto& entry : std::filesystem::directory_iterator(dirPath)) {
                    if (std::filesystem::is_directory(entry.path()) && !std::filesystem::is_symlink(entry.path())) {
                        removeDirectoryContents(entry.path());
                        std::filesystem::remove(entry.path());
                    } else {
                        std::filesystem::remove(entry.path());
                    }
                }
                LOG_INFO << "Successfully cleared directory contents: " << dirPath;
            } catch (const std::exception& e) {
                LOG_ERROR << "Error removing directory contents: " << e.what();
            }
        }
    }

    Options::Options() = default;
    
    Options::~Options() = default;

    void Options::registerHandlers(HttpAppFramework &app) {
        
        app.registerHandler(OPTIONS_PATH + "/get", [&app](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::registerHandlers";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/options/get");

            auto configValues = utils::getAllConfigValues();

            auto resp = HttpResponse::newHttpResponse();
            
            // Check if the client accepts HTML
            auto acceptHeader = req->getHeader("Accept");
            if (!acceptHeader.empty() && (acceptHeader.find("text/html") != std::string::npos)) {
                HttpViewData viewData;
                viewData.insert("options", configValues);
                viewData.insert("currentPage", std::string("options"));
                resp = HttpResponse::newHttpViewResponse("options.csp", viewData);
            } else {
                Json::Value jsonOptions;
                for (const auto& [key, value] : configValues) {
                    jsonOptions[key] = value;
                }
                resp->setStatusCode(k200OK);
                resp->setBody(Json::FastWriter().write(jsonOptions));
            }
            
            callback(resp);
        });

        app.registerHandler(OPTIONS_PATH + "/validate", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::validate";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/options/validate");

            // SECURITY: Restrict to POST method only
            if (req->getMethod() != HttpMethod::Post) {
                LOG_WARN << "SECURITY: Rejected non-POST request to /options/validate from " << AuditLog::getClientIP(req);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "This endpoint only accepts POST requests",
                    drogon::k405MethodNotAllowed,
                    "Method Not Allowed",
                    "METHOD_NOT_ALLOWED"
                );
                callback(resp);
                return;
            }

            auto body = req->getJsonObject();
            if (!body) {
                LOG_ERROR << "Options::validate: Invalid JSON body";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Invalid JSON request body",
                    drogon::k400BadRequest,
                    "Invalid Request",
                    "INVALID_JSON"
                );
                callback(resp);
                return;
            }

            std::string fieldName = body->get("field", "").asString();
            std::string fieldValue = body->get("value", "").asString();

            if (fieldName.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Field name is required",
                    drogon::k400BadRequest,
                    "Invalid Request",
                    "MISSING_FIELD_NAME"
                );
                callback(resp);
                return;
            }

            // SECURITY: Dynamic whitelist of allowed configuration field names
            // This prevents arbitrary field name injection and limits validation to known config keys
            // We use the actual configuration file as the source of truth - if a field exists in the
            // config, it's valid for validation. This makes the system self-maintaining.
            auto configValues = utils::getAllConfigValues();
            std::set<std::string> allowedFields;
            for (const auto& [key, value] : configValues) {
                allowedFields.insert(key);
            }

            if (allowedFields.find(fieldName) == allowedFields.end()) {
                LOG_WARN << "SECURITY: Rejected validation request for unknown field: " << fieldName << " from " << AuditLog::getClientIP(req);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Unknown configuration field: " + fieldName + ". Field must exist in configuration file.",
                    drogon::k400BadRequest,
                    "Invalid Field",
                    "UNKNOWN_FIELD"
                );
                callback(resp);
                return;
            }

            // SECURITY: Validate and canonicalize file paths to prevent path traversal attacks
            auto validateAndCanonicalizePath = [](const std::string& path) -> std::optional<std::string> {
                if (path.empty()) return path;
                
                try {
                    // Convert to absolute path and resolve . and .. components
                    std::filesystem::path fsPath(path);
                    std::filesystem::path canonicalPath;
                    
                    // Check if path exists - if so, canonicalize it
                    if (std::filesystem::exists(fsPath)) {
                        canonicalPath = std::filesystem::canonical(fsPath);
                    } else {
                        // For non-existent paths, make absolute and lexically normalize
                        canonicalPath = std::filesystem::absolute(fsPath).lexically_normal();
                    }
                    
                    // Reject paths containing .. after normalization (path traversal attempt)
                    std::string pathStr = canonicalPath.string();
                    if (pathStr.find("..") != std::string::npos) {
                        return std::nullopt;
                    }
                    
                    return pathStr;
                } catch (const std::filesystem::filesystem_error&) {
                    // Invalid path
                    return std::nullopt;
                }
            };

            Json::Value jsonResponse;
            jsonResponse["valid"] = true;
            jsonResponse["field"] = fieldName;

            // Validate based on field type
            if (fieldName == "CUSTOMER_KEY_FILE_PEM") {
                if (!fieldValue.empty()) {
                    // SECURITY: Canonicalize path to prevent traversal
                    auto canonicalPath = validateAndCanonicalizePath(fieldValue);
                    if (!canonicalPath) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Invalid or unsafe file path";
                    } else if (!std::filesystem::exists(*canonicalPath)) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Key file does not exist at specified path";
                    } else if (!std::filesystem::is_regular_file(*canonicalPath)) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Path exists but is not a regular file";
                    } else {
                        // Check if file is readable
                        std::ifstream testFile(*canonicalPath);
                        if (!testFile.is_open()) {
                            jsonResponse["valid"] = false;
                            jsonResponse["error"] = "File exists but is not readable";
                        }
                    }
                }
            } else if (fieldName == "GOLD_MASTER_OS_FILE") {
                if (fieldValue.empty()) {
                    jsonResponse["valid"] = false;
                    jsonResponse["error"] = "Gold master OS file path is mandatory";
                } else {
                    // SECURITY: Canonicalize path to prevent traversal
                    auto canonicalPath = validateAndCanonicalizePath(fieldValue);
                    if (!canonicalPath) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Invalid or unsafe file path";
                    } else if (!std::filesystem::exists(*canonicalPath)) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Image file does not exist at specified path";
                    } else if (!std::filesystem::is_regular_file(*canonicalPath)) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Path exists but is not a regular file";
                    } else {
                        // Check file extension - should be .img
                        std::string ext = std::filesystem::path(*canonicalPath).extension().string();
                        if (ext != ".img") {
                            jsonResponse["valid"] = false;
                            jsonResponse["error"] = "File should have .img extension (uncompressed image)";
                        }
                    }
                }
            } else if (fieldName == "RPI_SB_WORKDIR") {
                if (!fieldValue.empty()) {
                    // SECURITY: Canonicalize path to prevent traversal
                    auto canonicalPath = validateAndCanonicalizePath(fieldValue);
                    if (!canonicalPath) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Invalid or unsafe directory path";
                    } else if (std::filesystem::exists(*canonicalPath)) {
                        if (!std::filesystem::is_directory(*canonicalPath)) {
                            jsonResponse["valid"] = false;
                            jsonResponse["error"] = "Path exists but is not a directory";
                        }
                    } else {
                        // Check if parent directory exists
                        std::filesystem::path path(*canonicalPath);
                        std::filesystem::path parentPath = path.parent_path();
                        if (parentPath.empty()) {
                            parentPath = ".";
                        }
                        if (!std::filesystem::exists(parentPath)) {
                            jsonResponse["valid"] = false;
                            jsonResponse["error"] = "Parent directory does not exist";
                        } else if (!std::filesystem::is_directory(parentPath)) {
                            jsonResponse["valid"] = false;
                            jsonResponse["error"] = "Parent path exists but is not a directory";
                        }
                    }
                }
            } else if (fieldName == "RPI_SB_PROVISIONER_MANUFACTURING_DB") {
                if (fieldValue.empty()) {
                    jsonResponse["valid"] = false;
                    jsonResponse["error"] = "Manufacturing database path is mandatory";
                } else {
                    // SECURITY: Canonicalize path to prevent traversal
                    auto canonicalPath = validateAndCanonicalizePath(fieldValue);
                    if (!canonicalPath) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Invalid or unsafe file path";
                    } else if (!std::filesystem::exists(*canonicalPath)) {
                        // Check if parent directory exists
                        std::filesystem::path path(*canonicalPath);
                        std::filesystem::path parentPath = path.parent_path();
                        if (parentPath.empty()) {
                            parentPath = ".";
                        }
                        if (!std::filesystem::exists(parentPath)) {
                            jsonResponse["valid"] = false;
                            jsonResponse["error"] = "Parent directory does not exist";
                        } else if (!std::filesystem::is_directory(parentPath)) {
                            jsonResponse["valid"] = false;
                            jsonResponse["error"] = "Parent path exists but is not a directory";
                        } else {
                            jsonResponse["message"] = "File will be created on save";
                        }
                    } else if (std::filesystem::is_directory(*canonicalPath)) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Path exists but is a directory (expected file path)";
                    }
                }
            } else if (fieldName == "RPI_DEVICE_BOOTLOADER_CONFIG_FILE") {
                if (!fieldValue.empty()) {
                    // SECURITY: Canonicalize path to prevent traversal
                    auto canonicalPath = validateAndCanonicalizePath(fieldValue);
                    if (!canonicalPath) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Invalid or unsafe file path";
                    } else if (!std::filesystem::exists(*canonicalPath)) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Bootloader config file does not exist at specified path";
                    } else if (!std::filesystem::is_regular_file(*canonicalPath)) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Path exists but is not a regular file";
                    }
                }
            } else if (fieldName == "RPI_DEVICE_RETRIEVE_KEYPAIR") {
                if (!fieldValue.empty()) {
                    // SECURITY: Canonicalize path to prevent traversal
                    auto canonicalPath = validateAndCanonicalizePath(fieldValue);
                    if (!canonicalPath) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "Invalid or unsafe directory path";
                    } else if (std::filesystem::exists(*canonicalPath)) {
                        if (!std::filesystem::is_directory(*canonicalPath)) {
                            jsonResponse["valid"] = false;
                            jsonResponse["error"] = "Path exists but is not a directory";
                        }
                    } else {
                        std::filesystem::path path(*canonicalPath);
                        std::filesystem::path parentPath = path.parent_path();
                        if (parentPath.empty()) {
                            parentPath = ".";
                        }
                        if (!std::filesystem::exists(parentPath)) {
                            jsonResponse["valid"] = false;
                            jsonResponse["error"] = "Parent directory does not exist";
                        } else {
                            jsonResponse["message"] = "Directory will be created if needed";
                        }
                    }
                }
            } else if (fieldName == "RPI_DEVICE_FAMILY") {
                if (fieldValue != "4" && fieldValue != "5" && fieldValue != "2W") {
                    jsonResponse["valid"] = false;
                    jsonResponse["error"] = "Device family must be 4, 5, or 2W";
                }
            } else if (fieldName == "PROVISIONING_STYLE") {
                if (fieldValue != "secure-boot" && fieldValue != "fde-only" && fieldValue != "naked") {
                    jsonResponse["valid"] = false;
                    jsonResponse["error"] = "Provisioning style must be secure-boot, fde-only, or naked";
                }
            } else if (fieldName == "RPI_DEVICE_STORAGE_TYPE") {
                if (fieldValue != "sd" && fieldValue != "emmc" && fieldValue != "nvme") {
                    jsonResponse["valid"] = false;
                    jsonResponse["error"] = "Storage type must be sd, emmc, or nvme";
                }
            } else if (fieldName == "RPI_DEVICE_STORAGE_CIPHER") {
                if (!fieldValue.empty() && fieldValue != "aes-xts-plain64" && fieldValue != "xchacha12,aes-adiantum-plain64") {
                    jsonResponse["valid"] = false;
                    jsonResponse["error"] = "Cipher must be aes-xts-plain64 or xchacha12,aes-adiantum-plain64";
                }
            } else if (fieldName == "CUSTOMER_KEY_PKCS11_NAME") {
                if (!fieldValue.empty()) {
                    // Basic validation for PKCS11 format
                    if (fieldValue.find("pkcs11:") != 0) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "PKCS11 name must start with 'pkcs11:'";
                    } else if (fieldValue.find("object=") == std::string::npos) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "PKCS11 name must include 'object=' parameter";
                    } else if (fieldValue.find("type=private") == std::string::npos) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "PKCS11 name must include 'type=private' parameter";
                    }
                }
            } else if (fieldName == "RPI_DEVICE_RPIBOOT_GPIO") {
                if (!fieldValue.empty()) {
                    // Valid GPIO pins for RPIBOOT on Raspberry Pi 4 family: 2, 4, 5, 6, 7, 8
                    // These GPIOs are high by default and can enable RPIBOOT when pulled low
                    std::set<std::string> validGpioPins = {"2", "4", "5", "6", "7", "8"};
                    if (validGpioPins.find(fieldValue) == validGpioPins.end()) {
                        jsonResponse["valid"] = false;
                        jsonResponse["error"] = "GPIO pin must be one of: 2, 4, 5, 6, 7, or 8. GPIO 8 is recommended.";
                    }
                }
            }

            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            resp->setBody(Json::FastWriter().write(jsonResponse));
            callback(resp);
        });

        app.registerHandler(OPTIONS_PATH + "/set", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::set";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/options/set");

            // SECURITY: Validate CSRF token for browser requests
            // Only enforce if the X-CSRF-Token header is present (gradual rollout)
            if (!req->getHeader("X-CSRF-Token").empty()) {
                if (!utils::validateCsrfToken(req)) {
                    LOG_WARN << "SECURITY: CSRF validation failed for /options/set from " << AuditLog::getClientIP(req);
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        "Invalid or expired security token. Please refresh the page and try again.",
                        drogon::k403Forbidden,
                        "Security Error",
                        "CSRF_VALIDATION_FAILED"
                    );
                    callback(resp);
                    return;
                }
            }

            auto body = req->getJsonObject();
            if (!body) {
                LOG_ERROR << "Options::set: Invalid JSON body";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Invalid JSON request body",
                    drogon::k400BadRequest,
                    "Invalid Request",
                    "INVALID_JSON"
                );
                callback(resp);
                return;
            }
            std::map<std::string, std::string> existing_options = utils::getAllConfigValues();

            for (const auto &key : body->getMemberNames()) {
                LOG_INFO << "Options::set: " << key << " = " << body->get(key, "").asString();

                // Merge with new values from request
                existing_options[key] = body->get(key, "").asString();

                // Write back merged config to user config file
                std::ofstream config_write(utils::CONFIG_USER_PATH);
                if (!config_write.is_open()) {
                    LOG_ERROR << "Failed to open config file for writing";
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        "Failed to write configuration file",
                        drogon::k500InternalServerError,
                        "Config Error",
                        "CONFIG_WRITE_ERROR"
                    );
                    callback(resp);
                    return;
                }

                for (const auto &[k, v] : existing_options) {
                    config_write << k << "=" << v << "\n";
                }
                config_write.close();
            }

            // Check if RPI_SB_WORKDIR is set, and if so, clear its contents
            auto workdirValue = utils::getConfigValue("RPI_SB_WORKDIR");
            std::string workdir = workdirValue ? *workdirValue : "";
            if (!workdir.empty()) {
                if (std::filesystem::exists(workdir) && std::filesystem::is_directory(workdir)) {
                    LOG_INFO << "Removing contents of RPI_SB_WORKDIR at " << workdir;
                    removeDirectoryContents(workdir);
                } else {
                    LOG_WARN << "RPI_SB_WORKDIR path does not exist or is not a directory: " << workdir;
                }
            }

            // Check if manufacturing DB path is set and create if needed
            auto mfg_db_path = existing_options.find("RPI_SB_PROVISIONER_MANUFACTURING_DB");
            if (mfg_db_path != existing_options.end()) {
                if (!std::filesystem::exists(mfg_db_path->second)) {
                    std::ofstream mfg_db(mfg_db_path->second);
                    if (!mfg_db.is_open()) {
                        LOG_ERROR << "Failed to create manufacturing DB file at " << mfg_db_path->second;
                        
                        // Log failed file creation to audit log
                        AuditLog::logFileSystemAccess("CREATE", mfg_db_path->second, false);
                        
                        auto resp = provisioner::utils::createErrorResponse(
                            req,
                            "Failed to create manufacturing database file",
                            drogon::k500InternalServerError,
                            "Database Error",
                            "DB_CREATE_ERROR",
                            "Path: " + mfg_db_path->second
                        );
                        callback(resp);
                        return;
                    }
                    mfg_db.close();
                    
                    // Log successful file creation to audit log
                    AuditLog::logFileSystemAccess("CREATE", mfg_db_path->second, true);
                    
                    // Set root read-write permissions (0600)
                    try {
                        std::filesystem::permissions(mfg_db_path->second, 
                            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
                        
                        // Log successful permission change to audit log
                        AuditLog::logFileSystemAccess("CHMOD", mfg_db_path->second, true);
                    } catch (const std::filesystem::filesystem_error& e) {
                        LOG_ERROR << "Failed to set permissions on manufacturing DB file: " << e.what();
                        
                        // Log failed permission change to audit log
                        AuditLog::logFileSystemAccess("CHMOD", mfg_db_path->second, false, "", e.what());
                        
                        auto resp = provisioner::utils::createErrorResponse(
                            req,
                            "Failed to set permissions on manufacturing database file",
                            drogon::k500InternalServerError,
                            "Permission Error",
                            "DB_PERMISSION_ERROR",
                            e.what()
                        );
                        callback(resp);
                        return;
                    }
                }
            }

            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            callback(resp);
        });

        // Add a new endpoint to clear the workdir contents when an image is selected
        app.registerHandler(OPTIONS_PATH + "/clear-workdir", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::clear-workdir";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/options/clear-workdir");

            auto workdirValue = utils::getConfigValue("RPI_SB_WORKDIR");
            std::string workdir = workdirValue ? *workdirValue : "";

            // Check if workdir was found
            if (workdir.empty()) {
                LOG_INFO << "RPI_SB_WORKDIR not set in configuration";
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k200OK);
                callback(resp);
                return;
            }

            LOG_INFO << "Clearing contents of RPI_SB_WORKDIR: " << workdir;

            if (std::filesystem::exists(workdir)) {
                if (std::filesystem::is_directory(workdir)) {
                    // Log directory deletion to audit log
                    AuditLog::logFileSystemAccess("DELETE_CONTENTS", workdir, true);
                    
                    removeDirectoryContents(workdir);
                } else {
                    LOG_WARN << "RPI_SB_WORKDIR exists but is not a directory: " << workdir;
                }
            } else {
                LOG_INFO << "RPI_SB_WORKDIR does not exist: " << workdir << " - considered already cleared";
                // Log skipped operation to audit log
                AuditLog::logFileSystemAccess("SKIP_DELETE_CONTENTS", workdir, true, "", "Directory does not exist");
            }
            
            // Return success in all cases
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            callback(resp);
        });

        // CSRF token endpoint - generates a new token for the session
        app.registerHandler(OPTIONS_PATH + "/csrf-token", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::csrf-token";
            
            std::string sessionId = utils::getSessionIdFromRequest(req);
            std::string token = utils::CsrfTokenManager::getInstance().generateToken(sessionId);
            
            Json::Value response;
            response["token"] = token;
            
            auto resp = HttpResponse::newHttpJsonResponse(response);
            resp->setStatusCode(k200OK);
            callback(resp);
        });

        // Firmware selection handlers
        app.registerHandler(OPTIONS_PATH + "/firmware", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::firmware";
            
            AuditLog::logHandlerAccess(req, "/options/firmware");

            auto configValues = utils::getAllConfigValues();
            
            // Get device family from config
            std::string deviceFamily = "";
            auto familyIt = configValues.find("RPI_DEVICE_FAMILY");
            if (familyIt != configValues.end()) {
                deviceFamily = familyIt->second;
            }
            
            std::string chipNumber = utils::getChipNumberForFamily(deviceFamily);
            
            // Get firmware information using the helper
            auto firmwareInfoList = utils::scanFirmwareDirectory(deviceFamily);
            
            // Convert to map format for template compatibility
            std::vector<std::map<std::string, std::string>> firmwareList;
            for (const auto& info : firmwareInfoList) {
                std::map<std::string, std::string> fwMap;
                fwMap["version"] = info.version;
                fwMap["filename"] = info.filename;
                fwMap["filepath"] = info.filepath;
                fwMap["releaseChannel"] = info.releaseChannel;
                fwMap["size"] = std::to_string(info.size);
                firmwareList.push_back(fwMap);
            }
            
            // Get release notes
            std::string releaseNotes = "";
            if (!chipNumber.empty()) {
                std::string releaseNotesPath = "/lib/firmware/raspberrypi/bootloader-" + chipNumber + "/release-notes.md";
                if (std::filesystem::exists(releaseNotesPath)) {
                    std::ifstream notesFile(releaseNotesPath);
                    if (notesFile.is_open()) {
                        std::string line;
                        while (std::getline(notesFile, line)) {
                            releaseNotes += line + "\n";
                        }
                        notesFile.close();
                    }
                }
            }

            // Get currently selected firmware file
            std::string selectedFirmwareFile = "";
            auto firmwareFileIt = configValues.find("RPI_DEVICE_FIRMWARE_FILE");
            if (firmwareFileIt != configValues.end()) {
                selectedFirmwareFile = firmwareFileIt->second;
            }

            HttpViewData viewData;
            viewData.insert("deviceFamily", deviceFamily);
            viewData.insert("chipNumber", chipNumber);
            viewData.insert("firmwareList", firmwareList);
            viewData.insert("releaseNotes", releaseNotes);
            viewData.insert("selectedFirmwareFile", selectedFirmwareFile);
            viewData.insert("currentPage", std::string("firmware"));
            
            auto resp = HttpResponse::newHttpViewResponse("firmware.csp", viewData);
            callback(resp);
        });

        // Firmware list JSON endpoint for inline browser
        app.registerHandler(OPTIONS_PATH + "/firmware/list", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::firmware::list";
            
            AuditLog::logHandlerAccess(req, "/options/firmware/list");

            // SECURITY: Restrict to GET method only
            if (req->getMethod() != HttpMethod::Get) {
                LOG_WARN << "SECURITY: Rejected non-GET request to /options/firmware/list from " << AuditLog::getClientIP(req);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "This endpoint only accepts GET requests",
                    drogon::k405MethodNotAllowed,
                    "Method Not Allowed",
                    "METHOD_NOT_ALLOWED"
                );
                callback(resp);
                return;
            }

            auto configValues = utils::getAllConfigValues();
            
            // Get device family from config
            std::string deviceFamily = "";
            auto familyIt = configValues.find("RPI_DEVICE_FAMILY");
            if (familyIt != configValues.end()) {
                deviceFamily = familyIt->second;
            }
            
            std::string chipNumber = utils::getChipNumberForFamily(deviceFamily);
            
            // Get firmware information using the shared helper
            auto firmwareInfoList = utils::scanFirmwareDirectory(deviceFamily);
            
            // Convert to JSON
            Json::Value firmwareList(Json::arrayValue);
            for (const auto& info : firmwareInfoList) {
                Json::Value fw;
                fw["version"] = info.version;
                fw["filename"] = info.filename;
                fw["filepath"] = info.filepath;
                fw["releaseChannel"] = info.releaseChannel;
                fw["size"] = std::to_string(info.size);
                firmwareList.append(fw);
            }

            // Get currently selected firmware file
            std::string selectedFirmwareFile = "";
            auto firmwareFileIt = configValues.find("RPI_DEVICE_FIRMWARE_FILE");
            if (firmwareFileIt != configValues.end()) {
                selectedFirmwareFile = firmwareFileIt->second;
            }

            Json::Value jsonResponse;
            jsonResponse["deviceFamily"] = deviceFamily;
            jsonResponse["chipNumber"] = chipNumber;
            jsonResponse["firmwareList"] = firmwareList;
            jsonResponse["selectedFirmwareFile"] = selectedFirmwareFile;
            
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            resp->setBody(Json::FastWriter().write(jsonResponse));
            callback(resp);
        });

        app.registerHandler(OPTIONS_PATH + "/firmware/set", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::firmware::set - Method: " << req->getMethodString() 
                     << ", Content-Type: " << req->getHeader("Content-Type")
                     << ", Body length: " << req->getBody().length();
            
            AuditLog::logHandlerAccess(req, "/options/firmware/set");

            // SECURITY: Restrict to POST method only
            if (req->getMethod() != HttpMethod::Post) {
                LOG_WARN << "SECURITY: Rejected non-POST request to /options/firmware/set from " << AuditLog::getClientIP(req);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "This endpoint only accepts POST requests",
                    drogon::k405MethodNotAllowed,
                    "Method Not Allowed",
                    "METHOD_NOT_ALLOWED"
                );
                callback(resp);
                return;
            }

            // SECURITY: Validate CSRF token for browser requests
            if (!req->getHeader("X-CSRF-Token").empty()) {
                if (!utils::validateCsrfToken(req)) {
                    LOG_WARN << "SECURITY: CSRF validation failed for /options/firmware/set from " << AuditLog::getClientIP(req);
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        "Invalid or expired security token. Please refresh the page and try again.",
                        drogon::k403Forbidden,
                        "Security Error",
                        "CSRF_VALIDATION_FAILED"
                    );
                    callback(resp);
                    return;
                }
            }

            auto body = req->getJsonObject();
            if (!body) {
                // Log more details for debugging
                LOG_ERROR << "Failed to parse JSON body. Content-Type: " << req->getHeader("Content-Type") 
                          << ", Body length: " << req->getBody().length();
                if (req->getBody().length() < 1000) {
                    LOG_ERROR << "Body content: " << req->getBody();
                }
                
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Invalid JSON request body",
                    drogon::k400BadRequest,
                    "Invalid Request",
                    "INVALID_JSON"
                );
                callback(resp);
                return;
            }

            std::string selectedFirmware = body->get("firmware_path", "").asString();
            LOG_INFO << "Firmware selection request: " << selectedFirmware;
            
            // Empty path is valid - it means "use default firmware"
            if (!selectedFirmware.empty()) {
                // SECURITY: Validate the firmware path is within the allowed directory
                // Note: /lib/firmware may be a symlink to /usr/lib/firmware, so we need to
                // canonicalize the base path as well for proper comparison
                const std::string allowedFirmwareBaseRaw = "/lib/firmware/raspberrypi/bootloader-";
                std::string allowedFirmwareBase = allowedFirmwareBaseRaw;
                
                // Try to get canonical path of the base directory (minus the trailing "bootloader-")
                try {
                    std::filesystem::path basePath("/lib/firmware/raspberrypi");
                    if (std::filesystem::exists(basePath)) {
                        allowedFirmwareBase = std::filesystem::canonical(basePath).string() + "/bootloader-";
                    }
                } catch (...) {
                    // If canonicalization fails, use the raw path
                }
                
                try {
                    // Canonicalize to prevent path traversal
                    std::filesystem::path firmwarePath(selectedFirmware);
                    std::filesystem::path canonicalPath;
                    
                    if (std::filesystem::exists(firmwarePath)) {
                        canonicalPath = std::filesystem::canonical(firmwarePath);
                    } else {
                        auto resp = provisioner::utils::createErrorResponse(
                            req,
                            "Selected firmware file does not exist",
                            drogon::k400BadRequest,
                            "Invalid Request",
                            "FIRMWARE_NOT_FOUND"
                        );
                        callback(resp);
                        return;
                    }
                    
                    std::string canonicalStr = canonicalPath.string();
                    
                    LOG_DEBUG << "Firmware path validation: canonical=" << canonicalStr << ", allowedBase=" << allowedFirmwareBase;
                    
                    // Verify the path starts with the allowed firmware directory
                    if (canonicalStr.find(allowedFirmwareBase) != 0) {
                        LOG_WARN << "SECURITY: Rejected firmware path outside allowed directory: " << canonicalStr 
                                 << " (expected prefix: " << allowedFirmwareBase << ") from " << AuditLog::getClientIP(req);
                        auto resp = provisioner::utils::createErrorResponse(
                            req,
                            "Firmware path must be within the system firmware directory",
                            drogon::k400BadRequest,
                            "Invalid Path",
                            "INVALID_FIRMWARE_PATH"
                        );
                        callback(resp);
                        return;
                    }
                    
                    // Verify it's a regular file (not a directory or symlink to something else)
                    if (!std::filesystem::is_regular_file(canonicalPath)) {
                        auto resp = provisioner::utils::createErrorResponse(
                            req,
                            "Selected path is not a regular file",
                            drogon::k400BadRequest,
                            "Invalid Request",
                            "NOT_A_FILE"
                        );
                        callback(resp);
                        return;
                    }
                    
                    // Use the canonical path for storage
                    selectedFirmware = canonicalStr;
                    
                } catch (const std::filesystem::filesystem_error& e) {
                    LOG_ERROR << "Filesystem error validating firmware path: " << e.what();
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        "Invalid firmware path",
                        drogon::k400BadRequest,
                        "Invalid Request",
                        "INVALID_PATH"
                    );
                    callback(resp);
                    return;
                }
            }

            // Update config with the selected firmware path
            std::map<std::string, std::string> existing_options = utils::getAllConfigValues();
            existing_options["RPI_DEVICE_FIRMWARE_FILE"] = selectedFirmware;

            // Write back the updated config to user config file
            std::ofstream config_write(utils::CONFIG_USER_PATH);
            if (!config_write.is_open()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to write configuration file",
                    drogon::k500InternalServerError,
                    "Config Error",
                    "CONFIG_WRITE_ERROR"
                );
                callback(resp);
                return;
            }

            for (const auto &[k, v] : existing_options) {
                config_write << k << "=" << v << "\n";
            }
            config_write.close();

            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            callback(resp);
        });

        app.registerHandler(OPTIONS_PATH + "/firmware/notes/{version}", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback, const std::string &version) {
            LOG_INFO << "Options::firmware::notes";
            
            AuditLog::logHandlerAccess(req, "/options/firmware/notes");

            // SECURITY: Restrict to GET method only
            if (req->getMethod() != HttpMethod::Get) {
                LOG_WARN << "SECURITY: Rejected non-GET request to /options/firmware/notes from " << AuditLog::getClientIP(req);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "This endpoint only accepts GET requests",
                    drogon::k405MethodNotAllowed,
                    "Method Not Allowed",
                    "METHOD_NOT_ALLOWED"
                );
                callback(resp);
                return;
            }

            LOG_INFO << "Requested version: '" << version << "'";
            
            if (version.empty()) {
                LOG_ERROR << "Version parameter is empty";
                Json::Value errorResponse;
                errorResponse["error"] = "No version specified";
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k400BadRequest);
                resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                resp->setBody(Json::FastWriter().write(errorResponse));
                callback(resp);
                return;
            }

            auto configValues = utils::getAllConfigValues();
            std::string deviceFamily = "";
            auto familyIt = configValues.find("RPI_DEVICE_FAMILY");
            if (familyIt != configValues.end()) {
                deviceFamily = familyIt->second;
            }
            
            LOG_INFO << "Device family from config: '" << deviceFamily << "'";
            
            std::string chipNumber = "";
            if (deviceFamily == "4") {
                chipNumber = "2711";
            } else if (deviceFamily == "5") {
                chipNumber = "2712";
            } else {
                // If no device family is configured, default to 2712 (Pi 5)
                chipNumber = "2712";
                LOG_INFO << "No valid device family configured, defaulting to 2712";
            }
            
            LOG_INFO << "Using chip number: " << chipNumber;
            
            std::string releaseNotes = "";
            if (!chipNumber.empty()) {
                std::string releaseNotesPath = "/lib/firmware/raspberrypi/bootloader-" + chipNumber + "/release-notes.md";
                LOG_INFO << "Looking for release notes at: " << releaseNotesPath << " for version: " << version;
                if (std::filesystem::exists(releaseNotesPath)) {
                    std::ifstream notesFile(releaseNotesPath);
                    if (notesFile.is_open()) {
                        std::string line;
                        bool inVersionSection = false;
                        std::string currentVersion = "";
                        
                        while (std::getline(notesFile, line)) {
                            // Check if this is a version header (format: ## YYYY-MM-DD: Title)
                            std::regex versionHeaderRegex(R"(^##\s*(\d{4}-\d{2}-\d{2}))");
                            std::smatch match;
                            if (std::regex_search(line, match, versionHeaderRegex)) {
                                currentVersion = match[1].str();
                                LOG_INFO << "Found version header: " << currentVersion;
                                if (currentVersion == version) {
                                    LOG_INFO << "Found matching version section for: " << version;
                                    inVersionSection = true;
                                    releaseNotes += line + "\n";
                                } else {
                                    if (inVersionSection) {
                                        // We've reached the next version, stop collecting
                                        LOG_INFO << "Reached next version, stopping collection";
                                        break;
                                    }
                                }
                            } else if (inVersionSection) {
                                // Check if we've reached another version section (starts with ##)
                                if (line.find("##") == 0) {
                                    // This is a new version section, stop collecting
                                    break;
                                }
                                releaseNotes += line + "\n";
                            }
                        }
                        notesFile.close();
                    } else {
                        LOG_ERROR << "Failed to open release notes file: " << releaseNotesPath;
                    }
                } else {
                    LOG_ERROR << "Release notes file does not exist: " << releaseNotesPath;
                }
            } else {
                LOG_ERROR << "Invalid chip number for device family: " << deviceFamily;
            }

            LOG_INFO << "Release notes length: " << releaseNotes.length();
            
            // If we couldn't find any release notes, return an error
            if (releaseNotes.empty()) {
                LOG_ERROR << "No release notes found for version: " << version;
                Json::Value errorResponse;
                errorResponse["error"] = "No release notes found for version " + version;
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k404NotFound);
                resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
                resp->setBody(Json::FastWriter().write(errorResponse));
                callback(resp);
                return;
            }
            
            Json::Value jsonResponse;
            jsonResponse["version"] = version;
            jsonResponse["notes"] = releaseNotes;
            
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            resp->setBody(Json::FastWriter().write(jsonResponse));
            callback(resp);
        });

        // Key file upload handler
        app.registerHandler(OPTIONS_PATH + "/upload-key", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::upload-key";
            
            AuditLog::logHandlerAccess(req, "/options/upload-key");

            // SECURITY: Restrict to POST method only
            if (req->getMethod() != HttpMethod::Post) {
                LOG_WARN << "SECURITY: Rejected non-POST request to /options/upload-key from " << AuditLog::getClientIP(req);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "This endpoint only accepts POST requests",
                    drogon::k405MethodNotAllowed,
                    "Method Not Allowed",
                    "METHOD_NOT_ALLOWED"
                );
                callback(resp);
                return;
            }

            // SECURITY: Validate CSRF token for browser requests
            if (!req->getHeader("X-CSRF-Token").empty()) {
                if (!utils::validateCsrfToken(req)) {
                    LOG_WARN << "SECURITY: CSRF validation failed for /options/upload-key from " << AuditLog::getClientIP(req);
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        "Invalid or expired security token. Please refresh the page and try again.",
                        drogon::k403Forbidden,
                        "Security Error",
                        "CSRF_VALIDATION_FAILED"
                    );
                    callback(resp);
                    return;
                }
            }

            // Get the uploaded file
            MultiPartParser fileParser;
            if (fileParser.parse(req) != 0) {
                LOG_ERROR << "Failed to parse multipart form data";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to parse file upload",
                    drogon::k400BadRequest,
                    "Invalid Request",
                    "PARSE_ERROR"
                );
                callback(resp);
                return;
            }

            auto &files = fileParser.getFiles();
            if (files.empty()) {
                LOG_ERROR << "No files in upload request";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "No file provided",
                    drogon::k400BadRequest,
                    "Invalid Request",
                    "NO_FILE"
                );
                callback(resp);
                return;
            }

            const auto &file = files[0];
            
            // SECURITY: Validate file size (max 64KB for a key file - generous limit)
            constexpr size_t MAX_KEY_FILE_SIZE = 64 * 1024;
            if (file.fileLength() > MAX_KEY_FILE_SIZE) {
                LOG_WARN << "SECURITY: Rejected oversized key file: " << file.fileLength() << " bytes from " << AuditLog::getClientIP(req);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Key file too large. Maximum size is 64KB.",
                    drogon::k400BadRequest,
                    "File Too Large",
                    "FILE_TOO_LARGE"
                );
                callback(resp);
                return;
            }
            
            // SECURITY: Validate file extension
            std::string filename = file.getFileName();
            std::filesystem::path filePath(filename);
            std::string ext = filePath.extension().string();
            std::transform(ext.begin(), ext.end(), ext.begin(), ::tolower);
            
            if (ext != ".pem" && ext != ".key") {
                LOG_WARN << "SECURITY: Rejected file with invalid extension: " << ext << " from " << AuditLog::getClientIP(req);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Invalid file type. Only .pem and .key files are allowed.",
                    drogon::k400BadRequest,
                    "Invalid File Type",
                    "INVALID_FILE_TYPE"
                );
                callback(resp);
                return;
            }
            
            // SECURITY: Basic content validation - check for PEM header
            std::string_view fileContentView = file.fileContent();
            std::string fileContent(fileContentView.data(), fileContentView.size());
            if (fileContent.find("-----BEGIN") == std::string::npos) {
                LOG_WARN << "SECURITY: Rejected file without PEM header from " << AuditLog::getClientIP(req);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "File does not appear to be a valid PEM-encoded key. Expected '-----BEGIN' header.",
                    drogon::k400BadRequest,
                    "Invalid Key Format",
                    "INVALID_KEY_FORMAT"
                );
                callback(resp);
                return;
            }

            // Define the key storage directory
            std::string keyStorageDir = "/etc/rpi-sb-provisioner/keys";
            
            // Create the directory if it doesn't exist
            try {
                if (!std::filesystem::exists(keyStorageDir)) {
                    std::filesystem::create_directories(keyStorageDir);
                    // Set restrictive permissions on the keys directory
                    std::filesystem::permissions(keyStorageDir,
                        std::filesystem::perms::owner_all,
                        std::filesystem::perm_options::replace);
                }
            } catch (const std::filesystem::filesystem_error& e) {
                LOG_ERROR << "Failed to create keys directory: " << e.what();
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to create key storage directory",
                    drogon::k500InternalServerError,
                    "Storage Error",
                    "STORAGE_ERROR"
                );
                callback(resp);
                return;
            }

            // Generate a safe filename (sanitize the original name)
            std::string safeFilename = filePath.filename().string();
            // Remove any path components and suspicious characters
            safeFilename.erase(std::remove_if(safeFilename.begin(), safeFilename.end(), 
                [](char c) { return c == '/' || c == '\\' || c == '\0' || c == ':'; }), safeFilename.end());
            
            if (safeFilename.empty()) {
                safeFilename = "customer-key.pem";
            }

            std::string destPath = keyStorageDir + "/" + safeFilename;
            
            // Save the file
            try {
                file.saveAs(destPath);
                
                // Set restrictive permissions on the key file (owner read only)
                std::filesystem::permissions(destPath,
                    std::filesystem::perms::owner_read,
                    std::filesystem::perm_options::replace);
                
                AuditLog::logFileSystemAccess("UPLOAD_KEY", destPath, true);
                
            } catch (const std::exception& e) {
                LOG_ERROR << "Failed to save key file: " << e.what();
                AuditLog::logFileSystemAccess("UPLOAD_KEY", destPath, false, "", e.what());
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to save key file",
                    drogon::k500InternalServerError,
                    "Storage Error",
                    "SAVE_ERROR"
                );
                callback(resp);
                return;
            }

            // Update the config with the new key path
            std::map<std::string, std::string> existing_options = utils::getAllConfigValues();
            existing_options["CUSTOMER_KEY_FILE_PEM"] = destPath;
            // Clear PKCS11 setting when uploading a PEM key
            existing_options["CUSTOMER_KEY_PKCS11_NAME"] = "";

            std::ofstream config_write(utils::CONFIG_USER_PATH);
            if (!config_write.is_open()) {
                LOG_ERROR << "Failed to open config file for writing: " << utils::CONFIG_USER_PATH;
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to update configuration",
                    drogon::k500InternalServerError,
                    "Config Error",
                    "CONFIG_WRITE_ERROR"
                );
                callback(resp);
                return;
            }

            for (const auto &[k, v] : existing_options) {
                config_write << k << "=" << v << "\n";
            }
            config_write.close();

            // Return success with the path
            Json::Value jsonResponse;
            jsonResponse["success"] = true;
            jsonResponse["path"] = destPath;
            jsonResponse["filename"] = safeFilename;
            
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(drogon::CT_APPLICATION_JSON);
            resp->setBody(Json::FastWriter().write(jsonResponse));
            callback(resp);
        });
    }
}