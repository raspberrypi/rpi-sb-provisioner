#include "customisation.h"
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
         * @param app Reference to the Drogon HTTP application framework instance
         */
        app.registerHandler(CUSTOMISATION_PATH + "/list-scripts", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Customisation::list-scripts";

            Json::Value scripts;
            scripts["scripts"] = Json::Value(Json::arrayValue);

            namespace fs = std::filesystem;
            
            if (fs::exists(SCRIPTS_DIR) && fs::is_directory(SCRIPTS_DIR)) {
                EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
                const EVP_MD *md = EVP_sha256();
                unsigned char hash[EVP_MAX_MD_SIZE];
                unsigned int hash_len;
                char buffer[4096];
                
                for (const auto& entry : fs::directory_iterator(SCRIPTS_DIR)) {
                    if (fs::is_regular_file(entry.path())) {
                        Json::Value script;
                        script["filename"] = entry.path().filename().string();

                        // Get file permissions using C++ filesystem API
                        const auto perms = fs::status(entry.path()).permissions();
                        script["executable"] = ((perms & fs::perms::owner_exec) != fs::perms::none);

                        // Calculate SHA256
                        std::ifstream file(entry.path(), std::ios::binary);
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
                        }
                        EVP_MD_CTX_reset(mdctx);

                        scripts["scripts"].append(script);
                    }
                }
                EVP_MD_CTX_free(mdctx);
            }

            if (req->getHeader("Accept").find("text/html") != std::string::npos) {
                // Turn the JSON back into a Drogon Data structure
                drogon::HttpViewData data;
                for (const auto& script : scripts["scripts"]) {
                    data.insert(script["filename"].asString(), script.toStyledString());
                }
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
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Script name is required");
                callback(resp);
                return;
            }

            std::string scriptPath = SCRIPTS_DIR + filename;
            
            if (!std::filesystem::exists(scriptPath)) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Script file not found");
                callback(resp);
                return;
            }
            
            std::ifstream scriptFile(scriptPath);
            if (!scriptFile.is_open()) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Script file not found");
                callback(resp);
                return;
            }

            std::stringstream buffer;
            buffer << scriptFile.rdbuf();
            resp->setStatusCode(k200OK);

            auto acceptHeader = req->getHeader("accept");
            if (acceptHeader.find("text/html") != std::string::npos) {
                auto tmpl = drogon::app().getCustomConfig()["templates_path"].asString() + "/get_scripts.csp";
                drogon::HttpViewData data;
                data.insert("script_content", buffer.str());
                data.insert("script_name", filename);
                callback(HttpResponse::newHttpViewResponse("get-scripts.csp", data));
            } else {
                resp->setContentTypeCode(CT_TEXT_PLAIN);
                resp->setBody(buffer.str());
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
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Script name is required");
                callback(resp);
                return;
            }

            std::string scriptPath = SCRIPTS_DIR + filename;
            
            namespace fs = std::filesystem;
            std::error_code ec;
            if (!fs::remove(scriptPath, ec)) {
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Failed to delete script: " + ec.message());
            } else {
                resp->setStatusCode(k200OK);
                resp->setBody("Script deleted successfully");
            }
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
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Script name is required");
                callback(resp);
                return;
            }

            std::string scriptPath = SCRIPTS_DIR + filename;
            
            namespace fs = std::filesystem;
            if (!fs::exists(scriptPath)) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Script file not found");
                callback(resp);
                return;
            }
            
            // Set file permissions to 0644 (rw-r--r--)
            std::error_code ec;
            fs::permissions(scriptPath, 
                          fs::perms::owner_read | fs::perms::owner_write | fs::perms::group_read | fs::perms::others_read,
                          fs::perm_options::replace, ec);
            if (ec) {
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Failed to disable script");
            } else {
                resp->setStatusCode(k200OK);
                resp->setBody("Script disabled successfully");
            }
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
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Script name is required");
                callback(resp);
                return;
            }

            std::string scriptPath = SCRIPTS_DIR + filename;
            
            namespace fs = std::filesystem;
            if (!fs::exists(scriptPath)) {
                resp->setStatusCode(k404NotFound);
                resp->setBody("Script file not found");
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
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Failed to set script file permissions");
                callback(resp);
                return;
            }
            
            resp->setStatusCode(k200OK);
            resp->setBody("Script enabled successfully");
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
                    resp->setStatusCode(k405MethodNotAllowed);
                    resp->setBody("Method not allowed");
                    callback(resp);
                    return;
            }
            
            // Check if the request is multipart/form-data
            if (req->getContentType() != CT_MULTIPART_FORM_DATA) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Invalid content type");
                callback(resp);
                return;
            }

            // Parse the multipart/form-data request
            MultiPartParser fileUpload;
            if (fileUpload.parse(req) != 0 || !fileUpload.getFiles().size()) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Failed to parse form data or no file uploaded");
                callback(resp);
                return;
            }
            
            auto files = fileUpload.getFilesMap();
            auto it = files.find("script");
            if (it == files.end()) {
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Script file is required");
                callback(resp);
                return;
            }
            
            const auto& fileInfo = it->second;
            
            // Create directories if they don't exist
            namespace fs = std::filesystem;
            if (!fs::exists(SCRIPTS_DIR)) {
                std::error_code ec;
                fs::create_directories(SCRIPTS_DIR, ec);
                if (ec) {
                    resp->setStatusCode(k500InternalServerError);
                    resp->setBody("Failed to create scripts directory: " + ec.message());
                    callback(resp);
                    return;
                }
            }
            
            // Write the file content to the customisation directory
            std::string scriptPath = SCRIPTS_DIR + fileInfo.getFileName();
            std::ofstream file(scriptPath, std::ios::binary);
            if (!file.is_open()) {
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Failed to write script file");
                callback(resp);
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
                callback(HttpResponse::newHttpViewResponse("upload_script.csp", data));
            } else {
                resp->setStatusCode(k200OK);
                resp->setBody("Script file uploaded successfully");
                callback(resp);
            }
        });
    }
} // namespace provisioner