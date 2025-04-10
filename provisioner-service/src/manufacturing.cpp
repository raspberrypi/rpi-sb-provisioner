#include <drogon/drogon.h>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>

#include <filesystem>
#include <string>
#include <vector>
#include <fstream>
#include <sqlite3.h>

#include "include/manufacturing.h"
#include "utils.h"

namespace provisioner {

    Manufacturing::Manufacturing() = default;
    
    Manufacturing::~Manufacturing() = default;

    void Manufacturing::registerHandlers(HttpAppFramework &app) {
        app.registerHandler("/manu-db", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Manufacturing::manu-db";
            auto resp = HttpResponse::newHttpResponse();
            
            // Get manufacturing DB path from config
            std::string dbPath;
            std::ifstream configFile("/etc/rpi-sb-provisioner/config");
            std::string line;
            std::string errorMessage;
            std::vector<std::map<std::string, std::string>> devicesList;
            
            if (!configFile.is_open()) {
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

            while (std::getline(configFile, line)) {
                size_t delimiter_pos = line.find('=');
                if (delimiter_pos != std::string::npos) {
                    std::string key = line.substr(0, delimiter_pos);
                    if (key == "RPI_SB_PROVISIONER_MANUFACTURING_DB") {
                        dbPath = line.substr(delimiter_pos + 1);
                        break;
                    }
                }
            }
            configFile.close();
            
            if (dbPath.empty()) {
                LOG_ERROR << "Manufacturing database path not configured";
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Manufacturing database path not configured in settings",
                    drogon::k500InternalServerError,
                    "Configuration Error",
                    "DB_PATH_NOT_SET"
                );
                callback(resp);
                return;
            } else if (!std::filesystem::exists(dbPath)) {
                LOG_ERROR << "Manufacturing database file does not exist: " << dbPath;
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Manufacturing database file not found",
                    drogon::k500InternalServerError,
                    "Database Error",
                    "DB_FILE_NOT_FOUND",
                    "Path: " + dbPath
                );
                callback(resp);
                return;
            } else {
                // Open the database
                sqlite3 *db;
                int rc = sqlite3_open(dbPath.c_str(), &db);
                if (rc != SQLITE_OK) {
                    LOG_ERROR << "Failed to open manufacturing database: " << sqlite3_errmsg(db);
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        "Failed to open manufacturing database",
                        drogon::k500InternalServerError,
                        "Database Error",
                        "DB_OPEN_ERROR",
                        std::string(sqlite3_errmsg(db))
                    );
                    sqlite3_close(db);
                    callback(resp);
                    return;
                } else {
                    // Query all devices
                    const char *sql = "SELECT * FROM devices ORDER BY provision_ts DESC;";
                    sqlite3_stmt *stmt;
                    rc = sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr);
                    if (rc != SQLITE_OK) {
                        LOG_ERROR << "Failed to prepare SQL statement: " << sqlite3_errmsg(db);
                        auto resp = provisioner::utils::createErrorResponse(
                            req,
                            "Failed to query manufacturing database",
                            drogon::k500InternalServerError,
                            "Database Error",
                            "SQL_PREPARE_ERROR",
                            std::string(sqlite3_errmsg(db))
                        );
                        sqlite3_close(db);
                        callback(resp);
                        return;
                    } else {
                        // Get column count
                        int colCount = sqlite3_column_count(stmt);
                        
                        // Process each row
                        while ((rc = sqlite3_step(stmt)) == SQLITE_ROW) {
                            std::map<std::string, std::string> device;
                            
                            for (int i = 0; i < colCount; i++) {
                                const char* colName = sqlite3_column_name(stmt, i);
                                const char* value = reinterpret_cast<const char*>(sqlite3_column_text(stmt, i));
                                
                                device[colName] = value ? value : "";
                            }
                            
                            devicesList.push_back(device);
                        }
                        
                        if (rc != SQLITE_DONE) {
                            LOG_ERROR << "Error while fetching data: " << sqlite3_errmsg(db);
                            auto resp = provisioner::utils::createErrorResponse(
                                req,
                                "Error while fetching data from manufacturing database",
                                drogon::k500InternalServerError,
                                "Database Error",
                                "DB_FETCH_ERROR",
                                std::string(sqlite3_errmsg(db))
                            );
                            sqlite3_finalize(stmt);
                            sqlite3_close(db);
                            callback(resp);
                            return;
                        }
                        
                        sqlite3_finalize(stmt);
                        sqlite3_close(db);
                    }
                }
            }
            
            // Check if the client accepts HTML
            auto acceptHeader = req->getHeader("Accept");
            if (!acceptHeader.empty() && (acceptHeader.find("text/html") != std::string::npos)) {
                HttpViewData viewData;
                viewData.insert("devices", devicesList);
                viewData.insert("currentPage", std::string("manufacturing"));
                
                if (!errorMessage.empty()) {
                    viewData.insert("warning", errorMessage);
                }
                
                resp = HttpResponse::newHttpViewResponse("manufacturing.csp", viewData);
            } else {
                Json::Value devicesArray(Json::arrayValue);
                for (const auto& device : devicesList) {
                    Json::Value deviceObj;
                    for (const auto& [key, value] : device) {
                        deviceObj[key] = value;
                    }
                    devicesArray.append(deviceObj);
                }
                
                if (!errorMessage.empty()) {
                    auto resp = provisioner::utils::createErrorResponse(
                        req,
                        errorMessage,
                        drogon::k500InternalServerError,
                        "Database Error",
                        "DB_ERROR"
                    );
                    callback(resp);
                    return;
                } else {
                    resp->setStatusCode(k200OK);
                    resp->setContentTypeCode(CT_APPLICATION_JSON);
                    resp->setBody(Json::FastWriter().write(devicesArray));
                }
            }
            
            callback(resp);
        });
    }
} // namespace provisioner 