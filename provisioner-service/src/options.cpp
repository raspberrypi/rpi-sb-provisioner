#include <string_view>
#include <fstream>
#include <filesystem>

#include <options.h>
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
                    if (std::filesystem::is_directory(entry.path())) {
                        std::filesystem::remove_all(entry.path());
                    } else {
                        std::filesystem::remove(entry.path());
                    }
                }
                LOG_INFO << "Removed contents of directory: " << dirPath;
            } catch (const std::filesystem::filesystem_error& e) {
                LOG_ERROR << "Failed to remove directory contents: " << e.what();
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

            Json::Value options;
            std::ifstream config_file("/etc/rpi-sb-provisioner/config");
            std::string line;
            
            if (!config_file.is_open()) {
                LOG_ERROR << "Failed to open config file";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to read configuration file",
                    drogon::k500InternalServerError,
                    "Config Error",
                    "CONFIG_READ_ERROR"
                );
                callback(resp);
                return;
            }

            while (std::getline(config_file, line)) {
                // Skip commented lines
                if (!line.empty() && line[0] == '#') {
                    continue;
                }
                
                size_t delimiter_pos = line.find('=');
                if (delimiter_pos != std::string::npos) {
                    std::string key = line.substr(0, delimiter_pos);
                    std::string value = line.substr(delimiter_pos + 1);
                    options[key] = value;
                }
            }
            config_file.close();

            auto resp = HttpResponse::newHttpResponse();
            
            // Check if the client accepts HTML
            auto acceptHeader = req->getHeader("Accept");
            if (!acceptHeader.empty() && (acceptHeader.find("text/html") != std::string::npos)) {
                HttpViewData viewData;
                std::map<std::string, std::string> optionsMap;
                for (const auto& key : options.getMemberNames()) {
                    optionsMap[key] = options[key].asString();
                }
                viewData.insert("options", optionsMap);
                viewData.insert("currentPage", std::string("options"));
                resp = HttpResponse::newHttpViewResponse("options.csp", viewData);
            } else {
                resp->setStatusCode(k200OK);
                resp->setBody(Json::FastWriter().write(options));
            }
            
            callback(resp);
        });

        app.registerHandler(OPTIONS_PATH + "/set", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::set";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/options/set");

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
            std::map<std::string, std::string> existing_options;
            // Read existing config
            std::ifstream config_read("/etc/rpi-sb-provisioner/config");
            std::string line;
            
            if (config_read.is_open()) {
                while (std::getline(config_read, line)) {
                    // Skip commented lines
                    if (!line.empty() && line[0] == '#') {
                        continue;
                    }
                    
                    size_t delimiter_pos = line.find('=');
                    if (delimiter_pos != std::string::npos) {
                        std::string key = line.substr(0, delimiter_pos);
                        std::string value = line.substr(delimiter_pos + 1);
                        existing_options[key] = value;
                    }
                }
                config_read.close();
            }

            for (const auto &key : body->getMemberNames()) {
                LOG_INFO << "Options::set: " << key << " = " << body->get(key, "").asString();

                // Merge with new values from request
                existing_options[key] = body->get(key, "").asString();

                // Write back merged config
                std::ofstream config_write("/etc/rpi-sb-provisioner/config");
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
            auto workdir = existing_options.find("RPI_SB_WORKDIR");
            if (workdir != existing_options.end() && !workdir->second.empty()) {
                if (std::filesystem::exists(workdir->second) && std::filesystem::is_directory(workdir->second)) {
                    LOG_INFO << "Removing contents of RPI_SB_WORKDIR at " << workdir->second;
                    removeDirectoryContents(workdir->second);
                } else {
                    LOG_WARN << "RPI_SB_WORKDIR path does not exist or is not a directory: " << workdir->second;
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

            // Read config file to get RPI_SB_WORKDIR value
            std::ifstream config_file("/etc/rpi-sb-provisioner/config");
            std::string line;
            std::string workdir;
            
            if (!config_file.is_open()) {
                LOG_ERROR << "Failed to open config file to determine RPI_SB_WORKDIR";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to read configuration file",
                    drogon::k500InternalServerError,
                    "Config Error",
                    "CONFIG_READ_ERROR"
                );
                callback(resp);
                return;
            }

            // Find the RPI_SB_WORKDIR value
            while (std::getline(config_file, line)) {
                // Skip commented lines
                if (!line.empty() && line[0] == '#') {
                    continue;
                }
                
                size_t delimiter_pos = line.find('=');
                if (delimiter_pos != std::string::npos) {
                    std::string key = line.substr(0, delimiter_pos);
                    std::string value = line.substr(delimiter_pos + 1);
                    if (key == "RPI_SB_WORKDIR") {
                        workdir = value;
                        break;
                    }
                }
            }
            config_file.close();

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
    }
}