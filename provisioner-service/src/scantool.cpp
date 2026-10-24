#include <drogon/drogon.h>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>

#include <string>
#include <fstream>
#include <sqlite3.h>

#include "include/scantool.h"
#include "utils.h"
#include "auth.h"
#include "include/audit.h"
#include <algorithm>

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
        sqlite3_busy_timeout(db, 5000);

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
        rc = sqlite3_bind_text(stmt, 1, qrCodeValue.data(), static_cast<int>(qrCodeValue.size()), SQLITE_STATIC);
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
            viewData.insert("anonymous", auth::username(req).empty());
            
            auto resp = HttpResponse::newHttpViewResponse("scantool.csp", viewData);
            callback(resp);
        });
        
        // Whether a scanned code is a DUID in the manufacturing database. A
        // plain GET, so the scanner can be offered without signing in: the
        // answer is only known or not. POST is kept for existing scripts.
        app.registerHandler("/api/v2/verify-qrcode", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            AuditLog::logHandlerAccess(req, "/api/v2/verify-qrcode");
            std::string code;
            bool given = false;
            if (req->getMethod() == drogon::HttpMethod::Get) {
                code = req->getParameter("code");
                given = !code.empty();
            } else {
                auto json = req->getJsonObject();
                if (json && json->isObject() && (*json)["qrcode"].isString()) {
                    code = (*json)["qrcode"].asString();
                    given = true;
                }
            }
            // A blank code, or one a NUL cuts short, would match every record
            // without a DUID.
            const bool printable = std::all_of(code.begin(), code.end(),
                                               [](unsigned char c) { return c >= 0x20 && c != 0x7f; });
            if (!given || !printable || code.size() > 256 ||
                code.find_first_not_of(' ') == std::string::npos) {
                callback(provisioner::utils::createErrorResponse(
                    req, "Missing or invalid code", drogon::k400BadRequest,
                    "Parameter Error", "INVALID_PARAMETER"));
                return;
            }

            std::string errorMessage;
            const bool exists = checkQRCodeInManufacturingDB(code, errorMessage);
            if (!errorMessage.empty()) {
                callback(provisioner::utils::createErrorResponse(
                    req, errorMessage, drogon::k500InternalServerError, "Database Error", "DB_ERROR"));
                return;
            }

            Json::Value result;
            result["success"] = true;
            result["exists"] = exists;
            result["qrcode"] = code;
            callback(HttpResponse::newHttpJsonResponse(result));
        }, {Get, Post});
    }
} // namespace provisioner 