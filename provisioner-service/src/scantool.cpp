#include <drogon/drogon.h>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>

#include <string>
#include <fstream>
#include <sqlite3.h>

#include "include/scantool.h"
#include "utils.h"

namespace provisioner {

    ScanTool::ScanTool() = default;
    
    ScanTool::~ScanTool() = default;

    // Utility function to check if a QR code value exists in the manufacturing DB
    bool checkQRCodeInManufacturingDB(const std::string& qrCodeValue, std::string& errorMessage) {
        // Get manufacturing DB path from config
        auto dbPath = utils::getConfigValue("RPI_SB_PROVISIONER_MANUFACTURING_DB");
        if (!dbPath) {
            errorMessage = "Manufacturing database path not configured in settings";
            LOG_ERROR << errorMessage;
            return false;
        }
        
        // Open the database
        sqlite3 *db;
        int rc = sqlite3_open(dbPath->c_str(), &db);
        if (rc != SQLITE_OK) {
            errorMessage = "Failed to open manufacturing database: " + std::string(sqlite3_errmsg(db));
            LOG_ERROR << errorMessage;
            sqlite3_close(db);
            return false;
        }
        
        // Prepare SQL query to check if QR code value exists as rpi_duid
        std::string sql = "SELECT COUNT(*) FROM devices WHERE rpi_duid = ?;";
        sqlite3_stmt *stmt;
        rc = sqlite3_prepare_v2(db, sql.c_str(), -1, &stmt, nullptr);
        if (rc != SQLITE_OK) {
            errorMessage = "Failed to prepare SQL statement: " + std::string(sqlite3_errmsg(db));
            LOG_ERROR << errorMessage;
            sqlite3_close(db);
            return false;
        }
        
        // Bind the QR code value to the parameter
        rc = sqlite3_bind_text(stmt, 1, qrCodeValue.c_str(), -1, SQLITE_STATIC);
        if (rc != SQLITE_OK) {
            errorMessage = "Failed to bind parameter: " + std::string(sqlite3_errmsg(db));
            LOG_ERROR << errorMessage;
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            return false;
        }
        
        // Execute the query
        bool found = false;
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            int count = sqlite3_column_int(stmt, 0);
            found = (count > 0);
        }
        
        // Clean up
        sqlite3_finalize(stmt);
        sqlite3_close(db);
        
        return found;
    }

    void ScanTool::registerHandlers(HttpAppFramework &app) {
        // Register handler for the main scan page
        app.registerHandler("/scantool", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "ScanTool::scantool";
            
            HttpViewData viewData;
            viewData.insert("currentPage", std::string("scantool"));
            
            auto resp = HttpResponse::newHttpViewResponse("scantool.csp", viewData);
            callback(resp);
        });
        
        // Register API handler for QR code verification
        app.registerHandler("/api/v2/verify-qrcode", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            auto resp = HttpResponse::newHttpResponse();
            resp->setContentTypeCode(CT_APPLICATION_JSON);
            
            // Check if it's a POST request
            if (req->getMethod() != drogon::HttpMethod::Post) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Only POST method is allowed",
                    drogon::k405MethodNotAllowed,
                    "Method Error",
                    "METHOD_NOT_ALLOWED"
                );
                callback(errorResp);
                return;
            }
            
            // Parse JSON body
            try {
                auto json = req->getJsonObject();
                if (!json || !json->isMember("qrcode") || !(*json)["qrcode"].isString()) {
                    auto errorResp = provisioner::utils::createErrorResponse(
                        req,
                        "Missing or invalid 'qrcode' parameter in request body",
                        drogon::k400BadRequest,
                        "Parameter Error",
                        "INVALID_PARAMETER"
                    );
                    callback(errorResp);
                    return;
                }
                
                std::string qrCodeValue = (*json)["qrcode"].asString();
                std::string errorMessage;
                
                // Check if QR code value exists in manufacturing DB
                bool exists = checkQRCodeInManufacturingDB(qrCodeValue, errorMessage);
                
                if (!errorMessage.empty()) {
                    auto errorResp = provisioner::utils::createErrorResponse(
                        req,
                        errorMessage,
                        drogon::k500InternalServerError,
                        "Database Error",
                        "DB_ERROR"
                    );
                    callback(errorResp);
                    return;
                }
                
                // Create success response
                Json::Value result;
                result["success"] = true;
                result["exists"] = exists;
                result["qrcode"] = qrCodeValue;
                
                resp->setStatusCode(k200OK);
                resp->setBody(Json::FastWriter().write(result));
                callback(resp);
                
            } catch (const std::exception &e) {
                auto errorResp = provisioner::utils::createErrorResponse(
                    req,
                    "Error processing request: " + std::string(e.what()),
                    drogon::k500InternalServerError,
                    "Server Error",
                    "SERVER_ERROR"
                );
                callback(errorResp);
            }
        });
    }
} // namespace provisioner 