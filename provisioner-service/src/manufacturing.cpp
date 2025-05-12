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

    void Manufacturing::registerHandlers(HttpAppFramework &app) {
        // HTML view endpoint - now only serves the template without data
        app.registerHandler("/manu-db", [this](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Manufacturing::manu-db (HTML view)";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/manu-db");
            
            // Just serve the template - data will be loaded via JavaScript
            HttpViewData viewData;
            viewData.insert("currentPage", std::string("manufacturing"));
            viewData.insert("auto_refresh", true);
            
            auto resp = HttpResponse::newHttpViewResponse("manufacturing.csp", viewData);
            callback(resp);
        });
        
        // JSON API endpoint with optional pagination
        app.registerHandler("/api/v2/manufacturing", [this](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "Manufacturing::api/v2/manufacturing (JSON data)";
            
            // Add audit log entry for handler access
            AuditLog::logHandlerAccess(req, "/api/v2/manufacturing");
            
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
            
            // Get the database path from the config
            auto dbPath = utils::getConfigValue("RPI_SB_PROVISIONER_MANUFACTURING_DB");
            if (!dbPath) {
                LOG_ERROR << "Manufacturing database path not configured";
                auto resp = utils::createErrorResponse(
                    req,
                    "Manufacturing database path not configured in settings",
                    drogon::k500InternalServerError,
                    "Configuration Error",
                    "DB_PATH_NOT_SET"
                );
                callback(resp);
                return;
            }
            
            // Check if the database file exists
            if (!std::filesystem::exists(*dbPath)) {
                LOG_ERROR << "Manufacturing database file does not exist: " << *dbPath;
                
                // Log failed file access to audit log
                AuditLog::logFileSystemAccess("READ", *dbPath, false);
                
                auto resp = utils::createErrorResponse(
                    req,
                    "Manufacturing database file not found",
                    drogon::k500InternalServerError,
                    "Database Error",
                    "DB_FILE_NOT_FOUND",
                    "Path: " + *dbPath
                );
                callback(resp);
                return;
            }
            
            // Log successful database access to audit log
            AuditLog::logFileSystemAccess("READ", *dbPath, true);
            
            // Open the database
            sqlite3 *db;
            int rc = sqlite3_open(dbPath->c_str(), &db);
            if (rc != SQLITE_OK) {
                LOG_ERROR << "Failed to open manufacturing database: " << sqlite3_errmsg(db);
                auto resp = utils::createErrorResponse(
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
            }
            
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
                auto resp = utils::createErrorResponse(
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
            }
            
            std::vector<std::map<std::string, std::string>> devicesList;
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
                auto resp = utils::createErrorResponse(
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
            
            // Build the JSON response
            Json::Value devicesArray(Json::arrayValue);
            for (const auto& device : devicesList) {
                Json::Value deviceObj;
                for (const auto& [key, value] : device) {
                    deviceObj[key] = value;
                }
                devicesArray.append(deviceObj);
            }
            
            auto resp = HttpResponse::newHttpResponse();
            resp->setStatusCode(k200OK);
            resp->setContentTypeCode(CT_APPLICATION_JSON);
            resp->setBody(Json::FastWriter().write(devicesArray));
            callback(resp);
        });
    }
} // namespace provisioner 