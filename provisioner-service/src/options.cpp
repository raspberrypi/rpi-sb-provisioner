#include <string_view>
#include <fstream>
#include <filesystem>

#include <options.h>
#include <drogon/HttpAppFramework.h>

namespace provisioner {
    namespace {
        const std::string OPTIONS_PATH = "/options";
    }

    Options::Options() = default;
    
    Options::~Options() = default;

    void Options::registerHandlers(HttpAppFramework &app) {
        
        app.registerHandler(OPTIONS_PATH + "/get", [&app](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::registerHandlers";

            Json::Value options;
            std::ifstream config_file("/etc/rpi-sb-provisioner/config");
            std::string line;
            
            if (!config_file.is_open()) {
                LOG_ERROR << "Failed to open config file";
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k500InternalServerError);
                resp->setBody("Failed to read config");
                callback(resp);
                return;
            }

            while (std::getline(config_file, line)) {
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
                resp = HttpResponse::newHttpViewResponse("options.csp", viewData);
            } else {
                resp->setStatusCode(k200OK);
                resp->setBody(Json::FastWriter().write(options));
            }
            
            callback(resp);
        });

        app.registerHandler(OPTIONS_PATH + "/set", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Options::set";

            auto body = req->getJsonObject();
            if (!body) {
                LOG_ERROR << "Options::set: Invalid JSON body";
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k400BadRequest);
                resp->setBody("Invalid JSON body");
                callback(resp);
                return;
            }
            std::map<std::string, std::string> existing_options;
            // Read existing config
            std::ifstream config_read("/etc/rpi-sb-provisioner/config");
            std::string line;
            
            if (config_read.is_open()) {
                while (std::getline(config_read, line)) {
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
                    auto resp = HttpResponse::newHttpResponse();
                    resp->setStatusCode(k500InternalServerError);
                    resp->setBody("Failed to write config");
                    callback(resp);
                    return;
                }

                for (const auto &[k, v] : existing_options) {
                    config_write << k << "=" << v << "\n";
                }
                config_write.close();
            }

            // Check if manufacturing DB path is set and create if needed
            auto mfg_db_path = existing_options.find("RPI_SB_PROVISIONER_MANUFACTURING_DB");
            if (mfg_db_path != existing_options.end()) {
                if (!std::filesystem::exists(mfg_db_path->second)) {
                    std::ofstream mfg_db(mfg_db_path->second);
                    if (!mfg_db.is_open()) {
                        LOG_ERROR << "Failed to create manufacturing DB file at " << mfg_db_path->second;
                        auto resp = HttpResponse::newHttpResponse();
                        resp->setStatusCode(k500InternalServerError);
                        resp->setBody("Failed to create manufacturing DB file");
                        callback(resp);
                        return;
                    }
                    mfg_db.close();
                    
                    // Set root read-write permissions (0600)
                    try {
                        std::filesystem::permissions(mfg_db_path->second, 
                            std::filesystem::perms::owner_read | std::filesystem::perms::owner_write);
                    } catch (const std::filesystem::filesystem_error& e) {
                        LOG_ERROR << "Failed to set permissions on manufacturing DB file: " << e.what();
                        auto resp = HttpResponse::newHttpResponse();
                        resp->setStatusCode(k500InternalServerError);
                        resp->setBody("Failed to set permissions on manufacturing DB file");
                        callback(resp);
                        return;
                    }
                }
            }

            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            callback(resp);
        });
    }
}