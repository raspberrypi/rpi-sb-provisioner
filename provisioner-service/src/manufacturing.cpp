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
#include "include/audit.h"

namespace provisioner {

    Manufacturing::Manufacturing() = default;
    
    Manufacturing::~Manufacturing() = default;

    // Helper method to get manufacturing database devices
    std::pair<bool, std::vector<std::map<std::string, std::string>>> Manufacturing::getManufacturingDevices(
        const HttpRequestPtr &req, 
        int offset,
        int limit) {
        
        std::string dbPath;
        std::string errorMessage;
        std::vector<std::map<std::string, std::string>> devicesList;
        
        // Get manufacturing DB path from config
        std::ifstream configFile("/etc/rpi-sb-provisioner/config");
        std::string line;
        
        if (!configFile.is_open()) {
            LOG_ERROR << "Failed to open config file";
            
            // Log failed file access to audit log
            AuditLog::logFileSystemAccess("READ", "/etc/rpi-sb-provisioner/config", false);
            return {false, devicesList};
        }

        // Log successful file access to audit log
        AuditLog::logFileSystemAccess("READ", "/etc/rpi-sb-provisioner/config", true);

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
            return {false, devicesList};
        } else if (!std::filesystem::exists(dbPath)) {
            LOG_ERROR << "Manufacturing database file does not exist: " << dbPath;
            
            // Log failed file access to audit log
            AuditLog::logFileSystemAccess("READ", dbPath, false);
            return {false, devicesList};
        } else {
            // Log successful database access to audit log
            AuditLog::logFileSystemAccess("READ", dbPath, true);
            
            // Open the database
            sqlite3 *db;
            int rc = sqlite3_open(dbPath.c_str(), &db);
            if (rc != SQLITE_OK) {
                LOG_ERROR << "Failed to open manufacturing database: " << sqlite3_errmsg(db);
                sqlite3_close(db);
                return {false, devicesList};
            } else {
                // Prepare SQL with optional pagination
                std::string sql = "SELECT * FROM devices ORDER BY provision_ts DESC";
                if (limit > 0) {
                    sql += " LIMIT " + std::to_string(limit);
                    if (offset > 0) {
                        sql += " OFFSET " + std::to_string(offset);
                    }
                }
                sql += ";";
                
                sqlite3_stmt *stmt;
                rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
                if (rc != SQLITE_OK) {
                    LOG_ERROR << "Failed to prepare SQL statement: " << sqlite3_errmsg(db);
                    sqlite3_close(db);
                    return {false, devicesList};
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
                        sqlite3_finalize(stmt);
                        sqlite3_close(db);
                        return {false, devicesList};
                    }
                    
                    sqlite3_finalize(stmt);
                    sqlite3_close(db);
                }
            }
        }
        
        return {true, devicesList};
    }

    void Manufacturing::registerHandlers(HttpAppFramework &app) {
        // HTML view endpoint
        app.registerHandler("/manu-db", [this](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Manufacturing::manu-db (HTML view)";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/manu-db");
            
            auto [success, devicesList] = getManufacturingDevices(req, 0, -1);
            
            if (!success) {
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to retrieve manufacturing database data",
                    drogon::k500InternalServerError,
                    "Database Error",
                    "DB_ERROR"
                );
                callback(resp);
                return;
            }
            
            HttpViewData viewData;
            viewData.insert("devices", devicesList);
            viewData.insert("currentPage", std::string("manufacturing"));
            viewData.insert("auto_refresh", true);
            
            auto resp = HttpResponse::newHttpViewResponse("manufacturing.csp", viewData);
            callback(resp);
        });
        
        // JSON API endpoint with optional pagination
        app.registerHandler("/manu-db/api", [this](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Manufacturing::manu-db/api (JSON data)";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/manu-db/api");
            
            // Parse pagination parameters
            int offset = 0;
            int limit = -1;
            
            auto offsetParam = req->getParameter("offset");
            auto limitParam = req->getParameter("limit");
            
            if (!offsetParam.empty()) {
                try {
                    offset = std::stoi(offsetParam);
                    if (offset < 0) offset = 0;
                } catch (const std::exception& e) {
                    offset = 0;
                }
            }
            
            if (!limitParam.empty()) {
                try {
                    limit = std::stoi(limitParam);
                    if (limit < 1) limit = -1;
                } catch (const std::exception& e) {
                    limit = -1;
                }
            }
            
            auto [success, devicesList] = getManufacturingDevices(req, offset, limit);
            
            auto resp = HttpResponse::newHttpResponse();
            
            if (!success) {
                resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to retrieve manufacturing database data",
                    drogon::k500InternalServerError,
                    "Database Error",
                    "DB_ERROR"
                );
            } else {
                Json::Value devicesArray(Json::arrayValue);
                for (const auto& device : devicesList) {
                    Json::Value deviceObj;
                    for (const auto& [key, value] : device) {
                        deviceObj[key] = value;
                    }
                    devicesArray.append(deviceObj);
                }
                
                resp->setStatusCode(k200OK);
                resp->setContentTypeCode(CT_APPLICATION_JSON);
                resp->setBody(Json::FastWriter().write(devicesArray));
            }
            
            callback(resp);
        });
    }
} // namespace provisioner 