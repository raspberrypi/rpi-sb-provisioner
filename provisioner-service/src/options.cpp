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
            std::map<std::string, std::string> existing_options = utils::getAllConfigValues();

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
            
            // Map device family to chip number
            std::string chipNumber = "";
            if (deviceFamily == "4") {
                chipNumber = "2711";
            } else if (deviceFamily == "5") {
                chipNumber = "2712";
            }
            
            // Get firmware information
            std::vector<std::map<std::string, std::string>> firmwareList;
            std::string releaseNotes = "";
            
            if (!chipNumber.empty()) {
                std::string firmwareDir = "/lib/firmware/raspberrypi/bootloader-" + chipNumber;
                
                // Get release notes
                std::string releaseNotesPath = firmwareDir + "/release-notes.md";
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
                
                // Scan for firmware files in all release directories
                std::vector<std::string> releaseDirs = {"default", "latest", "beta", "stable", "critical"};
                std::map<std::string, std::vector<std::pair<std::string, std::string>>> versionToChannelsAndPaths; // Map version to (channel, filepath) pairs
                
                // First pass: collect all files and group by version
                for (const auto& releaseDir : releaseDirs) {
                    std::string releasePath = firmwareDir + "/" + releaseDir;
                    if (std::filesystem::exists(releasePath) && std::filesystem::is_directory(releasePath)) {
                        for (const auto& entry : std::filesystem::directory_iterator(releasePath)) {
                            if (entry.is_regular_file()) {
                                std::string filename = entry.path().filename().string();
                                if (filename.find("pieeprom-") == 0 && filename.ends_with(".bin")) {
                                    // Extract version from filename
                                    std::regex versionRegex(R"(pieeprom-(\d{4}-\d{2}-\d{2})\.bin)");
                                    std::smatch match;
                                    if (std::regex_search(filename, match, versionRegex)) {
                                        std::string version = match[1].str();
                                        std::string filepath = entry.path().string();
                                        
                                        // Add this channel and filepath for this version
                                        versionToChannelsAndPaths[version].push_back({releaseDir, filepath});
                                    }
                                }
                            }
                        }
                    }
                }
                
                // Second pass: for each version, pick the preferred channel and create firmware info
                for (const auto& [version, channelsAndPaths] : versionToChannelsAndPaths) {
                    // Find the preferred channel (default > latest > beta > stable > critical)
                    std::string preferredChannel = "";
                    std::string preferredFilepath = "";
                    
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
                    
                    // Create firmware info for this version
                    if (!preferredChannel.empty()) {
                        std::map<std::string, std::string> firmwareInfo;
                        firmwareInfo["version"] = version;
                        firmwareInfo["filename"] = std::filesystem::path(preferredFilepath).filename().string();
                        firmwareInfo["filepath"] = preferredFilepath;
                        firmwareInfo["releaseChannel"] = preferredChannel;
                        firmwareInfo["size"] = std::to_string(std::filesystem::file_size(preferredFilepath));
                        
                        firmwareList.push_back(firmwareInfo);
                    }
                }
                
                // Sort by version (newest first)
                std::sort(firmwareList.begin(), firmwareList.end(), 
                    [](const auto& a, const auto& b) {
                        return a.at("version") > b.at("version");
                    });
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

        app.registerHandler(OPTIONS_PATH + "/firmware/set", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::firmware::set";
            
            AuditLog::logHandlerAccess(req, "/options/firmware/set");

            auto body = req->getJsonObject();
            if (!body) {
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
            if (selectedFirmware.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "No firmware path specified",
                    drogon::k400BadRequest,
                    "Invalid Request",
                    "NO_FIRMWARE_PATH"
                );
                callback(resp);
                return;
            }

            // Validate that the firmware file exists
            if (!std::filesystem::exists(selectedFirmware)) {
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

            // Update config with the selected firmware path
            std::map<std::string, std::string> existing_options = utils::getAllConfigValues();
            existing_options["RPI_DEVICE_FIRMWARE_FILE"] = selectedFirmware;

            // Write back the updated config
            std::ofstream config_write("/etc/rpi-sb-provisioner/config");
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
    }
}