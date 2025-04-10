#include "customisation.h"
#include "utils.h"
#include <filesystem>
#include <fstream>
#include <sstream>
#include <iomanip>
#include <openssl/evp.h>
#include <openssl/sha.h>
#include <drogon/drogon.h>

namespace provisioner {
    Customisation::Customisation() = default;
    Customisation::~Customisation() = default;

    namespace {
        const std::string CUSTOMISATION_PATH = "/customisation";
        const std::string SCRIPTS_DIR = "/etc/rpi-sb-provisioner/scripts/";

        // Define available provisioners and stages
        const std::vector<std::string> PROVISIONERS = {
            "sb-provisioner",
            "fde-provisioner"
        };
        
        const std::vector<std::string> STAGES = {
            "bootfs-mounted",
            "rootfs-mounted",
            "post-flash"
        };

        // Description of each stage for display in the UI
        const std::map<std::string, std::string> STAGE_DESCRIPTIONS = {
            {"bootfs-mounted", "Executed after boot image is mounted, before modifications"},
            {"rootfs-mounted", "Executed after rootfs is mounted, before final packaging"},
            {"post-flash", "Executed after bootfs and rootfs have been flashed to the device"}
        };

        // Helper function to get script metadata
        Json::Value getScriptMetadata(const std::string& filename, bool includeContent = false) {
            namespace fs = std::filesystem;
            Json::Value script;
            std::string sanitized_filename = utils::sanitize_path_component(filename);
            std::string filepath = SCRIPTS_DIR + sanitized_filename;
            
            script["filename"] = filename;

            // Get file permissions to determine if script is enabled (executable)
            const auto perms = fs::status(filepath).permissions();
            script["executable"] = ((perms & fs::perms::owner_exec) != fs::perms::none);
            script["enabled"] = script["executable"];

            // Calculate SHA256
            EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
            const EVP_MD *md = EVP_sha256();
            unsigned char hash[EVP_MAX_MD_SIZE];
            unsigned int hash_len;
            char buffer[4096];
            
            std::ifstream file(filepath, std::ios::binary);
            if (file) {
                EVP_DigestInit_ex(mdctx, md, nullptr);
                
                while (file.read(buffer, sizeof(buffer))) {
                    EVP_DigestUpdate(mdctx, buffer, file.gcount());
                }
                if (file.gcount() > 0) {
                    EVP_DigestUpdate(mdctx, buffer, file.gcount());
                }
                
                EVP_DigestFinal_ex(mdctx, hash, &hash_len);

                std::stringstream ss;
                for (unsigned int i = 0; i < hash_len; i++) {
                    ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
                }
                script["sha256"] = ss.str();
                
                // Reset file position to beginning
                file.clear();
                file.seekg(0, std::ios::beg);
                
                // Include script content if requested
                if (includeContent) {
                    std::stringstream contentSs;
                    contentSs << file.rdbuf();
                    script["content"] = contentSs.str();
                }
            }
            EVP_MD_CTX_free(mdctx);
            
            // Extract provisioner and stage from filename
            for (const auto& provisioner : PROVISIONERS) {
                if (filename.find(provisioner) == 0) {
                    script["provisioner"] = provisioner;
                    std::string stagePart = filename.substr(provisioner.length() + 1);
                    // Remove .sh extension
                    std::string stage = stagePart.substr(0, stagePart.length() - 3);
                    script["stage"] = stage;
                    
                    // Add descriptions
                    if (STAGE_DESCRIPTIONS.find(stage) != STAGE_DESCRIPTIONS.end()) {
                        script["description"] = STAGE_DESCRIPTIONS.at(stage);
                    }
                    break;
                }
            }

            return script;
        }
    }
    
    void Customisation::registerHandlers(drogon::HttpAppFramework &app) {

        /**
         * @brief Registers HTTP handlers for customisation-related endpoints
         * 
         * This function sets up the HTTP handlers for managing customisation scripts.
         * It registers endpoints for listing, uploading, downloading and managing 
         * customisation scripts stored in /etc/rpi-sb-provisioner/scripts/.
         * 
         * The handlers support both HTML and JSON responses based on the Accept header.
         * Scripts are validated for permissions and checksums are calculated using SHA256.
         *
         * Customisation scripts can be automatically executed during provisioning if they
         * follow specific naming patterns:
         * - "<provisioner-name>-bootfs-mounted.sh": Executed after boot image is mounted, before modifications
         * - "<provisioner-name>-rootfs-mounted.sh": Executed after rootfs is mounted, before final packaging
         * - "<provisioner-name>-post-flash.sh": Executed after bootfs and rootfs have been flashed to the device
         *
         * Where <provisioner-name> is one of:
         * - "sb-provisioner" for secure boot provisioning
         * - "fde-provisioner" for full disk encryption provisioning
         *
         * bootfs-mounted and rootfs-mounted scripts receive two arguments:
         * 1. Path to the mounted boot image
         * 2. Path to the mounted rootfs image
         *
         * Post-flash scripts receive three arguments:
         * 1. Fastboot device specifier (for use with fastboot commands)
         * 2. Target device serial number
         * 3. Device storage type (e.g., "mmcblk0" or "nvme0n1")
         * 
         * @param app Reference to the Drogon HTTP application framework instance
         */
        app.registerHandler(CUSTOMISATION_PATH + "/list-scripts", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Customisation::list-scripts";

            Json::Value scripts;
            scripts["scripts"] = Json::Value(Json::arrayValue);

            namespace fs = std::filesystem;
            
            if (fs::exists(SCRIPTS_DIR) && fs::is_directory(SCRIPTS_DIR)) {
                for (const auto& entry : fs::directory_iterator(SCRIPTS_DIR)) {
                    if (fs::is_regular_file(entry.path())) {
                        Json::Value script = getScriptMetadata(entry.path().filename().string());
                        script["exists"] = true;
                        scripts["scripts"].append(script);
                    }
                }
            }
            
            // Add hook points for missing scripts
            for (const auto& provisioner : PROVISIONERS) {
                for (const auto& stage : STAGES) {
                    std::string hookFilename = provisioner + "-" + stage + ".sh";
                    
                    // Check if this hook already exists in the scripts list
                    bool exists = false;
                    for (const auto& script : scripts["scripts"]) {
                        if (script["filename"].asString() == hookFilename) {
                            exists = true;
                            break;
                        }
                    }
                    
                    // If it doesn't exist, add a placeholder for the UI
                    if (!exists) {
                        Json::Value hookPoint;
                        hookPoint["filename"] = hookFilename;
                        hookPoint["provisioner"] = provisioner;
                        hookPoint["stage"] = stage;
                        hookPoint["exists"] = false;
                        hookPoint["enabled"] = false;
                        hookPoint["executable"] = false;
                        
                        // Add description
                        if (STAGE_DESCRIPTIONS.find(stage) != STAGE_DESCRIPTIONS.end()) {
                            hookPoint["description"] = STAGE_DESCRIPTIONS.at(stage);
                        }
                        
                        scripts["scripts"].append(hookPoint);
                    }
                }
            }

            if (req->getHeader("Accept").find("text/html") != std::string::npos) {
                // Turn the JSON back into a Drogon Data structure
                drogon::HttpViewData data;
                
                // Log scripts for debugging
                LOG_INFO << "Scripts data: " << Json::FastWriter().write(scripts["scripts"]);
                
                data.insert("scripts", scripts["scripts"]);
                data.insert("provisioners", PROVISIONERS);
                data.insert("stages", STAGES);
                data.insert("currentPage", std::string("customisation"));
                auto resp = drogon::HttpResponse::newHttpViewResponse("list_scripts.csp", data);
                resp->setStatusCode(k200OK);
                callback(resp);
            } else {
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k200OK);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody(Json::FastWriter().write(scripts));
                callback(resp);
            }
        });

        /**
         * @brief Lists all script files in the customisation directory
         * 
         * @details This endpoint returns a JSON array containing information about all script files
         * in /etc/rpi-sb-provisioner/scripts/. For each script, it includes:
         * - filename: The name of the script file
         * - executable: Boolean indicating if the script has execute permissions
         * - sha256: SHA256 hash of the script contents for verification
         *
         * @param req The HTTP request
         * @param callback The callback function to send the HTTP response
         *
         * @return void
         *
         * @note The response is always JSON formatted with Content-Type application/json
         */
        app.registerHandler(CUSTOMISATION_PATH + "/get-script", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Customisation::get-script";
            auto resp = HttpResponse::newHttpResponse();
            auto filename = req->getParameter("script");
            if (filename.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Script name is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_SCRIPT_NAME"
                );
                callback(resp);
                return;
            }

            std::string sanitized_filename = utils::sanitize_path_component(filename);
            std::string scriptPath = SCRIPTS_DIR + sanitized_filename;
            
            if (!std::filesystem::exists(scriptPath)) {
                // Check if this is a known hook point
                bool isKnownHook = false;
                std::string provisioner, stage;
                
                for (const auto& p : PROVISIONERS) {
                    for (const auto& s : STAGES) {
                        std::string hookName = p + "-" + s + ".sh";
                        if (hookName == filename) {
                            isKnownHook = true;
                            provisioner = p;
                            stage = s;
                            break;
                        }
                    }
                    if (isKnownHook) break;
                }
                
                if (isKnownHook) {
                    // Create a new script with default content
                    std::string defaultContent = "#!/bin/sh\n\n";
                    
                    if (stage == "post-flash") {
                        defaultContent += "# This script runs after images have been flashed to the device\n";
                        defaultContent += "# Arguments:\n";
                        defaultContent += "# $1 - Fastboot device specifier\n";
                        defaultContent += "# $2 - Target device serial number\n";
                        defaultContent += "# $3 - Device storage type (e.g., mmcblk0 or nvme0n1)\n\n";
                        defaultContent += "FASTBOOT_DEVICE_SPECIFIER=\"$1\"\n";
                        defaultContent += "TARGET_DEVICE_SERIAL=\"$2\"\n";
                        defaultContent += "STORAGE_TYPE=\"$3\"\n\n";
                        defaultContent += "echo \"Running post-flash customisation for ${TARGET_DEVICE_SERIAL}\"\n\n";
                        defaultContent += "# Example: Run a fastboot command\n";
                        defaultContent += "# fastboot -s \"${FASTBOOT_DEVICE_SPECIFIER}\" getvar version\n\n";
                        defaultContent += "# Exit with success\nexit 0\n";
                    } else if (stage == "bootfs-mounted") {
                        defaultContent += "# This script runs when " + stage + " for " + provisioner + "\n";
                        defaultContent += "# Arguments:\n";
                        defaultContent += "# $1 - Path to mounted boot image\n";
                        defaultContent += "# $2 - Path to mounted rootfs image\n\n";
                        defaultContent += "BOOT_MOUNT=\"$1\"\n";
                        defaultContent += "ROOTFS_MOUNT=\"$2\"\n\n";
                        defaultContent += "echo \"Running " + stage + " customisation\"\n";
                        defaultContent += "echo \"Boot mount: ${BOOT_MOUNT}\"\n";
                        defaultContent += "echo \"Rootfs mount: ${ROOTFS_MOUNT}\"\n\n";
                        defaultContent += "# Example: Modify boot configuration\n";
                        defaultContent += "# echo \"dtparam=watchdog=off\" >> \"${BOOT_MOUNT}/config.txt\"\n\n";
                        defaultContent += "# Exit with success\nexit 0\n";
                    } else if (stage == "rootfs-mounted") {
                        defaultContent += "# This script runs when " + stage + " for " + provisioner + "\n";
                        defaultContent += "# Arguments:\n";
                        defaultContent += "# $1 - Path to mounted boot image\n";
                        defaultContent += "# $2 - Path to mounted rootfs image\n\n";
                        defaultContent += "BOOT_MOUNT=\"$1\"\n";
                        defaultContent += "ROOTFS_MOUNT=\"$2\"\n\n";
                        defaultContent += "echo \"Running " + stage + " customisation\"\n";
                        defaultContent += "echo \"Boot mount: ${BOOT_MOUNT}\"\n";
                        defaultContent += "echo \"Rootfs mount: ${ROOTFS_MOUNT}\"\n\n";
                        defaultContent += "# Example: Modify boot configuration\n";
                        defaultContent += "echo \"Adding entry to hosts file for $1 during $2 stage\"\n\n";
                        defaultContent += "echo \"10.0.0.100 custom-host\" >> ${ROOTFS_MOUNT}/etc/hosts\n\n";
                        defaultContent += "# Exit with success\nexit 0\n";
                        
                    }
                    
                    auto acceptHeader = req->getHeader("accept");
                    if (acceptHeader.find("text/html") != std::string::npos) {
                        drogon::HttpViewData data;
                        data.insert("script_content", defaultContent);
                        data.insert("script_name", filename);
                        data.insert("script_exists", false);
                        data.insert("script_enabled", false);
                        data.insert("currentPage", std::string("customisation"));
                        callback(HttpResponse::newHttpViewResponse("get_script.csp", data));
                        return;
                    } else {
                        Json::Value response;
                        response["exists"] = false;
                        response["filename"] = filename;
                        response["content"] = defaultContent;
                        response["enabled"] = false;
                        
                        resp->setStatusCode(k200OK);
                        resp->setContentTypeCode(CT_APPLICATION_JSON);
                        resp->setBody(Json::FastWriter().write(response));
                        callback(resp);
                        return;
                    }
                } else {
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        "The requested script file could not be found",
                        drogon::k400BadRequest,
                        "Script Not Found", 
                        "SCRIPT_NOT_FOUND",
                        "Script path: " + scriptPath
                    );
                    callback(resp);
                    return;
                }
            }
            
            std::ifstream scriptFile(scriptPath);
            if (!scriptFile.is_open()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "The requested script file could not be opened",
                    drogon::k400BadRequest,
                    "Script Not Found",
                    "SCRIPT_NOT_FOUND",
                    "Script path: " + scriptPath
                );
                callback(resp);
                return;
            }

            std::stringstream buffer;
            buffer << scriptFile.rdbuf();
            
            // Get script metadata
            Json::Value scriptMetadata = getScriptMetadata(sanitized_filename, true);

            auto acceptHeader = req->getHeader("accept");
            if (acceptHeader.find("text/html") != std::string::npos) {
                drogon::HttpViewData data;
                data.insert("script_content", buffer.str());
                data.insert("script_name", filename);
                data.insert("script_exists", true);
                data.insert("script_enabled", scriptMetadata["enabled"].asBool());
                data.insert("currentPage", std::string("customisation"));
                callback(HttpResponse::newHttpViewResponse("get_script.csp", data));
            } else {
                Json::Value response;
                response["exists"] = true;
                response["filename"] = filename;
                response["content"] = buffer.str();
                response["enabled"] = scriptMetadata["enabled"].asBool();
                
                resp->setStatusCode(k200OK);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody(Json::FastWriter().write(response));
                callback(resp);
            }
        });

        /**
         * @brief Retrieves a script file from the customisation directory
         * 
         * @details This endpoint retrieves the contents of a script file from /etc/rpi-sb-provisioner/scripts/
         * based on the script name provided in the URL parameter. The script contents are returned as plain text.
         * If the script is not found or cannot be read, an appropriate error response is returned.
         *
         * @param req The HTTP request containing the script name parameter
         * @param callback The callback function to send the HTTP response
         *
         * @return void
         *
         * @throws k400BadRequest if script parameter is missing
         * @throws k404NotFound if script file does not exist
         */
        app.registerHandler(CUSTOMISATION_PATH + "/delete-script", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Customisation::delete-script";
            auto resp = HttpResponse::newHttpResponse();
            auto filename = req->getParameter("script");
            if (filename.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Script name is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_SCRIPT_NAME"
                );
                callback(resp);
                return;
            }

            std::string scriptPath = SCRIPTS_DIR + filename;
            
            namespace fs = std::filesystem;
            std::error_code ec;
            if (!fs::remove(scriptPath, ec)) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to delete script file",
                    drogon::k500InternalServerError,
                    "Deletion Error",
                    "SCRIPT_DELETE_ERROR",
                    ec.message()
                );
                callback(errorResp);
                return;
            } 
            
            resp->setStatusCode(k200OK);
            resp->setBody("Script deleted successfully");
            callback(resp);
        });

        /**
         * @brief Disables a script file in the customisation directory
         * 
         * @details This endpoint disables a script file in the customisation directory
         * by changing its permissions to 0644. If the script file does not exist or
         * cannot be modified, an appropriate error response is returned.
         *
         * @param req The HTTP request
         * @param callback The callback function to send the HTTP response
         *
         * @return void
         *
         * @throws k400BadRequest if script parameter is missing
         * @throws k500InternalServerError if script file cannot be modified
         */
        app.registerHandler(CUSTOMISATION_PATH + "/disable-script", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Customisation::disable-script";
            auto resp = HttpResponse::newHttpResponse();
            auto filename = req->getParameter("script");
            if (filename.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Script name is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_SCRIPT_NAME"
                );
                callback(resp);
                return;
            }

            std::string scriptPath = SCRIPTS_DIR + filename;
            
            namespace fs = std::filesystem;
            if (!fs::exists(scriptPath)) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "The requested script file could not be found",
                    drogon::k400BadRequest,
                    "Script Not Found",
                    "SCRIPT_NOT_FOUND",
                    "Script path: " + scriptPath
                );
                callback(resp);
                return;
            }
            
            // Set file permissions to 0644 (rw-r--r--)
            std::error_code ec;
            fs::permissions(scriptPath, 
                          fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read,
                          fs::perm_options::replace, ec);
            if (ec) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to disable script file",
                    drogon::k500InternalServerError,
                    "Permission Error",
                    "SCRIPT_PERMISSION_ERROR",
                    ec.message()
                );
                callback(errorResp);
                return;
            }
            
            resp->setStatusCode(k200OK);
            resp->setBody("Script disabled successfully");
            callback(resp);
        });

        /**
         * @brief Enables a script file in the customisation directory
         * 
         * @details This endpoint enables a script file in the customisation directory
         * by changing its permissions to 0755. If the script file does not exist or
         * cannot be modified, an appropriate error response is returned.
         *
         * @param req The HTTP request
         * @param callback The callback function to send the HTTP response
         *
         * @return void
         *
         * @throws k400BadRequest if script parameter is missing
         * @throws k500InternalServerError if script file cannot be modified
         */
        app.registerHandler(CUSTOMISATION_PATH + "/enable-script", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Customisation::enable-script";
            auto resp = HttpResponse::newHttpResponse();
            auto filename = req->getParameter("script");
            if (filename.empty()) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Script name is required",
                    drogon::k400BadRequest,
                    "Missing Parameter",
                    "MISSING_SCRIPT_NAME"
                );
                callback(resp);
                return;
            }

            std::string sanitized_filename = utils::sanitize_path_component(filename);
            std::string scriptPath = SCRIPTS_DIR + sanitized_filename;
            
            namespace fs = std::filesystem;
            if (!fs::exists(scriptPath)) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "The requested script file could not be found",
                    drogon::k400BadRequest,
                    "Script Not Found",
                    "SCRIPT_NOT_FOUND",
                    "Script path: " + scriptPath
                );
                callback(resp);
                return;
            }
            
            // Set file permissions to 0755 (rwxr-xr-x)
            std::error_code ec;
            fs::permissions(scriptPath, 
                          fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec,
                          fs::perm_options::replace, ec);
            if (ec) {
                LOG_ERROR << "Failed to set script file permissions";
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to enable script file",
                    drogon::k500InternalServerError,
                    "Permission Error",
                    "SCRIPT_PERMISSION_ERROR",
                    ec.message()
                );
                callback(errorResp);
                return;
            }
            
            resp->setStatusCode(k200OK);
            resp->setBody("Script enabled successfully");
            callback(resp);
        });

        /**
         * @brief Saves or creates a script file in the customisation directory
         * 
         * @details This endpoint allows for creating a new script or updating 
         * an existing script file in the customisation directory.
         *
         * @param req The HTTP request containing script name and content
         * @param callback The callback function to send the HTTP response
         *
         * @return void
         */
        app.registerHandler(CUSTOMISATION_PATH + "/save-script", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Customisation::save-script";
            auto resp = HttpResponse::newHttpResponse();
            
            if (req->getMethod() != HttpMethod::Post) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "This endpoint only accepts POST requests",
                    drogon::k405MethodNotAllowed,
                    "Method Not Allowed",
                    "METHOD_NOT_ALLOWED"
                );
                callback(errorResp);
                return;
            }
            
            auto json = req->getJsonObject();
            if (!json) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Invalid JSON request body",
                    drogon::k400BadRequest,
                    "Invalid Request",
                    "INVALID_JSON"
                );
                callback(errorResp);
                return;
            }
            
            if (!json->isMember("filename") || !json->isMember("content")) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Filename and content are required fields",
                    drogon::k400BadRequest,
                    "Missing Fields",
                    "MISSING_REQUIRED_FIELDS"
                );
                callback(errorResp);
                return;
            }
            
            std::string filename = (*json)["filename"].asString();
            std::string content = (*json)["content"].asString();
            bool shouldEnable = false;
            
            if (json->isMember("enabled")) {
                shouldEnable = (*json)["enabled"].asBool();
            }
            
            // Create directories if they don't exist
            namespace fs = std::filesystem;
            if (!fs::exists(SCRIPTS_DIR)) {
                std::error_code ec;
                fs::create_directories(SCRIPTS_DIR, ec);
                if (ec) {
                    auto errorResp = provisioner::utils::createErrorResponse(
                        req,
                        "Failed to create scripts directory",
                        drogon::k500InternalServerError,
                        "Directory Error",
                        "DIR_CREATE_ERROR",
                        ec.message()
                    );
                    callback(errorResp);
                    return;
                }
            }
            
            // Write the script content
            std::string sanitized_filename = utils::sanitize_path_component(filename);
            std::string scriptPath = SCRIPTS_DIR + sanitized_filename;
            std::ofstream file(scriptPath, std::ios::binary);
            if (!file.is_open()) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to write script file",
                    drogon::k500InternalServerError,
                    "File Error",
                    "FILE_WRITE_ERROR",
                    "Could not open file for writing: " + scriptPath
                );
                callback(errorResp);
                return;
            }
            
            file.write(content.c_str(), content.size());
            file.close();
            
            // Set appropriate permissions based on enabled status
            std::error_code ec;
            if (shouldEnable) {
                // Set file permissions to 0755 (rwxr-xr-x)
                fs::permissions(scriptPath, 
                              fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec,
                              fs::perm_options::replace, ec);
            } else {
                // Set file permissions to 0644 (rw-r--r--)
                fs::permissions(scriptPath, 
                              fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read,
                              fs::perm_options::replace, ec);
            }
            
            if (ec) {
                LOG_ERROR << "Failed to set script file permissions";
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to set script file permissions",
                    drogon::k500InternalServerError,
                    "File Error",
                    "FILE_PERMISSION_ERROR",
                    "Could not set execute permissions on script file: " + scriptPath
                );
                callback(errorResp);
                return;
            }
            
            // Get updated script metadata
            Json::Value scriptMetadata = getScriptMetadata(sanitized_filename);
            
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_APPLICATION_JSON);
            resp->setBody(Json::FastWriter().write(scriptMetadata));
            callback(resp);
        });

        /**
         * @brief Uploads a script file to the customisation directory
         * 
         * @details This endpoint allows users to upload a script file to the customisation directory
         * 
         * @param req The HTTP request containing the script file to be uploaded
         * @param callback The callback function to send the HTTP response
         *
         * @return void
         *
         * @throws k400BadRequest if script parameter is missing
         * @throws k500InternalServerError if script file cannot be uploaded
         */
        app.registerHandler(CUSTOMISATION_PATH + "/upload-script", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Customisation::upload-script";
            auto resp = HttpResponse::newHttpResponse();

            switch (req->getMethod()) {
                case HttpMethod::Post:
                    break;
                case HttpMethod::Get:
                    break;
                // Deliberately fall through to the default case
                case HttpMethod::Delete:
                case HttpMethod::Options:
                case HttpMethod::Put:
                case HttpMethod::Patch:
                default:
                    auto errorResp = provisioner::utils::createErrorResponse(
                        req,
                        "This endpoint only accepts POST and GET requests",
                        drogon::k405MethodNotAllowed,
                        "Method Not Allowed",
                        "METHOD_NOT_ALLOWED"
                    );
                    callback(errorResp);
                    return;
            }
            
            // Check if the request is multipart/form-data
            if (req->getContentType() != CT_MULTIPART_FORM_DATA) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Content type must be multipart/form-data",
                    drogon::k400BadRequest,
                    "Invalid Content Type",
                    "INVALID_CONTENT_TYPE"
                );
                callback(errorResp);
                return;
            }

            // Parse the multipart/form-data request
            MultiPartParser fileUpload;
            if (fileUpload.parse(req) != 0 || !fileUpload.getFiles().size()) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to parse form data or no file uploaded",
                    drogon::k400BadRequest,
                    "Upload Error",
                    "FORM_PARSE_ERROR"
                );
                callback(errorResp);
                return;
            }
            
            auto files = fileUpload.getFilesMap();
            auto it = files.find("script");
            if (it == files.end()) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Script file is required in the form data with field name 'script'",
                    drogon::k400BadRequest,
                    "Missing File",
                    "MISSING_SCRIPT_FILE"
                );
                callback(errorResp);
                return;
            }
            
            const auto& fileInfo = it->second;
            
            // Create directories if they don't exist
            namespace fs = std::filesystem;
            if (!fs::exists(SCRIPTS_DIR)) {
                std::error_code ec;
                fs::create_directories(SCRIPTS_DIR, ec);
                if (ec) {
                    auto errorResp = provisioner::utils::createErrorResponse(
                        req,
                        "Failed to create scripts directory",
                        drogon::k500InternalServerError,
                        "Directory Error",
                        "DIR_CREATE_ERROR",
                        ec.message()
                    );
                    callback(errorResp);
                    return;
                }
            }
            
            // Write the file content to the customisation directory
            std::string sanitized_filename = utils::sanitize_path_component(fileInfo.getFileName());
            std::string scriptPath = SCRIPTS_DIR + sanitized_filename;
            std::ofstream file(scriptPath, std::ios::binary);
            if (!file.is_open()) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to write script file",
                    drogon::k500InternalServerError,
                    "File Error",
                    "FILE_WRITE_ERROR",
                    "Could not open file for writing: " + scriptPath
                );
                callback(errorResp);
                return;
            }

            file.write(fileInfo.fileContent().data(), fileInfo.fileContent().size());
            file.close();
            
            // Set file permissions to 0755 (rwxr-xr-x)
            std::error_code ec;
            fs::permissions(scriptPath, 
                          fs::perms::owner_all | fs::perms::group_read | fs::perms::group_exec | fs::perms::others_read | fs::perms::others_exec,
                          fs::perm_options::replace, ec);
            if (ec) {
                LOG_ERROR << "Failed to set script file permissions";
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Failed to set script file permissions");
                callback(resp);
                return;
            }
            
            auto acceptHeader = req->getHeader("accept");
            if (!acceptHeader.empty() && acceptHeader.find("text/html") != std::string::npos) {
                drogon::HttpViewData data;
                data.insert("filename", fileInfo.getFileName());
                data.insert("success", true);
                data.insert("currentPage", std::string("customisation"));
                callback(HttpResponse::newHttpViewResponse("upload_script.csp", data));
            } else {
                resp->setStatusCode(k200OK);
                resp->setBody("Script file uploaded successfully");
                callback(resp);
            }
        });

        /**
         * @brief Lists all available hook points for customisation scripts
         * 
         * @details This endpoint returns information about all possible hook points
         * for customisation scripts, including available provisioners and stages.
         *
         * @param req The HTTP request
         * @param callback The callback function to send the HTTP response
         *
         * @return void
         */
        app.registerHandler(CUSTOMISATION_PATH + "/list-hooks", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Customisation::list-hooks";
            
            Json::Value response;
            response["provisioners"] = Json::Value(Json::arrayValue);
            response["stages"] = Json::Value(Json::arrayValue);
            response["hooks"] = Json::Value(Json::arrayValue);
            
            // Add provisioners
            for (const auto& provisioner : PROVISIONERS) {
                response["provisioners"].append(provisioner);
            }
            
            // Add stages with descriptions
            for (const auto& stage : STAGES) {
                Json::Value stageInfo;
                stageInfo["name"] = stage;
                if (STAGE_DESCRIPTIONS.find(stage) != STAGE_DESCRIPTIONS.end()) {
                    stageInfo["description"] = STAGE_DESCRIPTIONS.at(stage);
                }
                response["stages"].append(stageInfo);
            }
            
            // Add all possible hook points
            for (const auto& provisioner : PROVISIONERS) {
                for (const auto& stage : STAGES) {
                    Json::Value hook;
                    std::string filename = provisioner + "-" + stage + ".sh";
                    
                    hook["filename"] = filename;
                    hook["provisioner"] = provisioner;
                    hook["stage"] = stage;
                    
                    // Check if script exists
                    std::string scriptPath = SCRIPTS_DIR + filename;
                    namespace fs = std::filesystem;
                    if (fs::exists(scriptPath)) {
                        hook["exists"] = true;
                        
                        // Get permissions to determine if enabled
                        const auto perms = fs::status(scriptPath).permissions();
                        hook["enabled"] = ((perms & fs::perms::owner_exec) != fs::perms::none);
                    } else {
                        hook["exists"] = false;
                        hook["enabled"] = false;
                    }
                    
                    response["hooks"].append(hook);
                }
            }
            
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_APPLICATION_JSON);
            resp->setBody(Json::FastWriter().write(response));
            callback(resp);
        });
    }
} // namespace provisioner