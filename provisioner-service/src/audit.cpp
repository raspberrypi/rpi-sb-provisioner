#include <drogon/drogon.h>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <drogon/HttpTypes.h>

#include <string>
#include <vector>
#include <map>
#include <chrono>
#include <ctime>
#include <iomanip>
#include <sstream>
#include <filesystem>
#include <sqlite3.h>

#include "include/audit.h"
#include "utils.h"

namespace provisioner {

    // Initialize static members
    const std::string AuditLog::AUDIT_DB_PATH = "/srv/rpi-sb-provisioner/audit.db";
    std::mutex AuditLog::dbMutex;

    AuditLog::AuditLog() {
        // Ensure database exists on instantiation
        ensureAuditDatabase();
    }
    
    AuditLog::~AuditLog() = default;

    bool AuditLog::ensureAuditDatabase() {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        sqlite3* db;
        int rc = sqlite3_open(AUDIT_DB_PATH.c_str(), &db);
        
        if (rc != SQLITE_OK) {
            LOG_ERROR << "Failed to open audit database: " << sqlite3_errmsg(db);
            sqlite3_close(db);
            return false;
        }
        
        // Create the audit log table if it doesn't exist
        const char* create_table_sql = 
            "CREATE TABLE IF NOT EXISTS audit_log ("
            "id INTEGER PRIMARY KEY AUTOINCREMENT,"
            "timestamp TEXT NOT NULL,"
            "event_type TEXT NOT NULL,"
            "client_ip TEXT,"
            "user_agent TEXT,"
            "handler_path TEXT,"
            "operation TEXT,"
            "target_path TEXT,"
            "success INTEGER,"
            "username TEXT,"
            "additional_info TEXT"
            ");";
            
        char* errMsg = nullptr;
        rc = sqlite3_exec(db, create_table_sql, nullptr, nullptr, &errMsg);
        
        if (rc != SQLITE_OK) {
            LOG_ERROR << "Failed to create audit log table: " << errMsg;
            sqlite3_free(errMsg);
            sqlite3_close(db);
            return false;
        }
        
        // Create an index on timestamp for faster queries
        const char* create_index_sql = 
            "CREATE INDEX IF NOT EXISTS idx_timestamp ON audit_log(timestamp);";
            
        rc = sqlite3_exec(db, create_index_sql, nullptr, nullptr, &errMsg);
        
        if (rc != SQLITE_OK) {
            LOG_ERROR << "Failed to create index on audit log table: " << errMsg;
            sqlite3_free(errMsg);
            sqlite3_close(db);
            return false;
        }
        
        sqlite3_close(db);
        
        // Set the file permissions to 0640 (owner:rw, group:r, other:-)
        try {
            std::filesystem::permissions(AUDIT_DB_PATH, 
                std::filesystem::perms::owner_read | 
                std::filesystem::perms::owner_write |
                std::filesystem::perms::group_read);
        } catch (const std::filesystem::filesystem_error& e) {
            LOG_ERROR << "Failed to set permissions on audit DB file: " << e.what();
            return false;
        }
        
        return true;
    }
    
    std::string AuditLog::getClientIP(const HttpRequestPtr &req) {
        std::string clientIP = req->getPeerAddr().toIp();
        
        // Check for X-Forwarded-For header (if behind a proxy)
        auto xff = req->getHeader("X-Forwarded-For");
        if (!xff.empty()) {
            // Extract the original client IP (first in the list)
            size_t commaPos = xff.find(',');
            if (commaPos != std::string::npos) {
                clientIP = xff.substr(0, commaPos);
            } else {
                clientIP = xff;
            }
        }
        
        return clientIP;
    }
    
    void AuditLog::logHandlerAccess(const HttpRequestPtr &req, const std::string &handlerPath) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        sqlite3* db;
        int rc = sqlite3_open(AUDIT_DB_PATH.c_str(), &db);
        
        if (rc != SQLITE_OK) {
            LOG_ERROR << "Failed to open audit database for handler access logging: " << sqlite3_errmsg(db);
            sqlite3_close(db);
            return;
        }
        
        // Get current timestamp in ISO 8601 format
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::tm tm_now;
        localtime_r(&time_t_now, &tm_now);
        std::stringstream timestamp;
        timestamp << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");
        
        std::string clientIP = getClientIP(req);
        std::string userAgent = req->getHeader("User-Agent");
        
        const char* insert_sql = 
            "INSERT INTO audit_log (timestamp, event_type, client_ip, user_agent, handler_path) "
            "VALUES (?, 'HANDLER_ACCESS', ?, ?, ?);";
            
        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            LOG_ERROR << "Failed to prepare audit log statement: " << sqlite3_errmsg(db);
            sqlite3_close(db);
            return;
        }
        
        std::string timestampStr = timestamp.str();
        sqlite3_bind_text(stmt, 1, timestampStr.c_str(), timestampStr.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, clientIP.c_str(), clientIP.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, userAgent.c_str(), userAgent.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 4, handlerPath.c_str(), handlerPath.length(), SQLITE_TRANSIENT);
        
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            LOG_ERROR << "Failed to insert handler access audit log entry: " << sqlite3_errmsg(db);
        }
        
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    
    void AuditLog::logFileSystemAccess(const std::string &operation, const std::string &path,
                                       bool success, const std::string &username,
                                       const std::string &additional_info) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        sqlite3* db;
        int rc = sqlite3_open(AUDIT_DB_PATH.c_str(), &db);
        
        if (rc != SQLITE_OK) {
            LOG_ERROR << "Failed to open audit database for filesystem access logging: " << sqlite3_errmsg(db);
            sqlite3_close(db);
            return;
        }
        
        // Get current timestamp in ISO 8601 format
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::tm tm_now;
        localtime_r(&time_t_now, &tm_now);
        std::stringstream timestamp;
        timestamp << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");
        
        const char* insert_sql = 
            "INSERT INTO audit_log (timestamp, event_type, operation, target_path, success, username, additional_info) "
            "VALUES (?, 'FILE_ACCESS', ?, ?, ?, ?, ?);";
            
        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            LOG_ERROR << "Failed to prepare audit log statement: " << sqlite3_errmsg(db);
            sqlite3_close(db);
            return;
        }
        
        std::string timestampStr = timestamp.str();
        sqlite3_bind_text(stmt, 1, timestampStr.c_str(), timestampStr.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, operation.c_str(), operation.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, path.c_str(), path.length(), SQLITE_TRANSIENT);
        sqlite3_bind_int(stmt, 4, success ? 1 : 0);
        sqlite3_bind_text(stmt, 5, username.c_str(), username.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 6, additional_info.c_str(), additional_info.length(), SQLITE_TRANSIENT);
        
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            LOG_ERROR << "Failed to insert filesystem access audit log entry: " << sqlite3_errmsg(db);
        }
        
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    
    void AuditLog::logSystemdAccess(const std::string &service, const std::string &username) {
        std::lock_guard<std::mutex> lock(dbMutex);
        
        sqlite3* db;
        int rc = sqlite3_open(AUDIT_DB_PATH.c_str(), &db);
        
        if (rc != SQLITE_OK) {
            LOG_ERROR << "Failed to open audit database for systemd access logging: " << sqlite3_errmsg(db);
            sqlite3_close(db);
            return;
        }
        
        // Get current timestamp in ISO 8601 format
        auto now = std::chrono::system_clock::now();
        auto time_t_now = std::chrono::system_clock::to_time_t(now);
        std::tm tm_now;
        localtime_r(&time_t_now, &tm_now);
        std::stringstream timestamp;
        timestamp << std::put_time(&tm_now, "%Y-%m-%d %H:%M:%S");
        
        const char* insert_sql = 
            "INSERT INTO audit_log (timestamp, event_type, operation, target_path, username) "
            "VALUES (?, 'SYSTEMD_LOG_ACCESS', 'VIEW', ?, ?);";
            
        sqlite3_stmt* stmt;
        rc = sqlite3_prepare_v2(db, insert_sql, -1, &stmt, nullptr);
        
        if (rc != SQLITE_OK) {
            LOG_ERROR << "Failed to prepare audit log statement: " << sqlite3_errmsg(db);
            sqlite3_close(db);
            return;
        }
        
        std::string timestampStr = timestamp.str();
        sqlite3_bind_text(stmt, 1, timestampStr.c_str(), timestampStr.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 2, service.c_str(), service.length(), SQLITE_TRANSIENT);
        sqlite3_bind_text(stmt, 3, username.c_str(), username.length(), SQLITE_TRANSIENT);
        
        rc = sqlite3_step(stmt);
        if (rc != SQLITE_DONE) {
            LOG_ERROR << "Failed to insert systemd access audit log entry: " << sqlite3_errmsg(db);
        }
        
        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }
    
    void AuditLog::registerHandlers(HttpAppFramework &app) {
        app.registerHandler("/auditlog", [](const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
            LOG_INFO << "AuditLog::auditlog";
            
            // Log this access to the audit log
            AuditLog::logHandlerAccess(req, "/auditlog");
            
            // Get query parameters for filtering
            std::string eventType = req->getParameter("event_type");
            std::string startDate = req->getParameter("start_date");
            std::string endDate = req->getParameter("end_date");
            std::string limit = req->getParameter("limit");  // Default to 100 entries
            
            // Open the audit database
            sqlite3* db;
            int rc = sqlite3_open(AUDIT_DB_PATH.c_str(), &db);
            
            if (rc != SQLITE_OK) {
                LOG_ERROR << "Failed to open audit database: " << sqlite3_errmsg(db);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to open audit database",
                    drogon::k500InternalServerError,
                    "Database Error",
                    "DB_OPEN_ERROR",
                    std::string(sqlite3_errmsg(db))
                );
                sqlite3_close(db);
                callback(resp);
                return;
            }
            
            // Build query with optional filters
            std::stringstream query;
            query << "SELECT * FROM audit_log WHERE 1=1 ";
            
            if (!eventType.empty()) {
                query << "AND event_type = ? ";
            }
            
            if (!startDate.empty()) {
                query << "AND timestamp >= ? ";
            }
            
            if (!endDate.empty()) {
                query << "AND timestamp <= ? ";
            }
            
            query << "ORDER BY timestamp DESC LIMIT ?;";
            
            sqlite3_stmt* stmt;
            rc = sqlite3_prepare_v2(db, query.str().c_str(), -1, &stmt, nullptr);
            
            if (rc != SQLITE_OK) {
                LOG_ERROR << "Failed to prepare audit log query: " << sqlite3_errmsg(db);
                auto resp = provisioner::utils::createErrorResponse(
                    req,
                    "Failed to query audit log",
                    drogon::k500InternalServerError,
                    "Database Error",
                    "QUERY_ERROR",
                    std::string(sqlite3_errmsg(db))
                );
                sqlite3_close(db);
                callback(resp);
                return;
            }
            
            // Bind parameters if provided
            int bindIndex = 1;
            
            if (!eventType.empty()) {
                sqlite3_bind_text(stmt, bindIndex++, eventType.c_str(), -1, SQLITE_STATIC);
            }
            
            if (!startDate.empty()) {
                sqlite3_bind_text(stmt, bindIndex++, startDate.c_str(), -1, SQLITE_STATIC);
            }
            
            if (!endDate.empty()) {
                sqlite3_bind_text(stmt, bindIndex++, endDate.c_str(), -1, SQLITE_STATIC);
            }
            
            // Always bind the limit parameter
            sqlite3_bind_text(stmt, bindIndex, limit.c_str(), -1, SQLITE_STATIC);
            
            // Process query results
            std::vector<std::map<std::string, std::string>> auditEntries;
            
            while (sqlite3_step(stmt) == SQLITE_ROW) {
                std::map<std::string, std::string> entry;
                
                entry["id"] = std::to_string(sqlite3_column_int(stmt, 0));
                entry["timestamp"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 1));
                entry["event_type"] = reinterpret_cast<const char*>(sqlite3_column_text(stmt, 2));
                
                // Handle nullable columns
                const unsigned char* clientIp = sqlite3_column_text(stmt, 3);
                if (clientIp) entry["client_ip"] = reinterpret_cast<const char*>(clientIp);
                
                const unsigned char* userAgent = sqlite3_column_text(stmt, 4);
                if (userAgent) entry["user_agent"] = reinterpret_cast<const char*>(userAgent);
                
                const unsigned char* handlerPath = sqlite3_column_text(stmt, 5);
                if (handlerPath) entry["handler_path"] = reinterpret_cast<const char*>(handlerPath);
                
                const unsigned char* operation = sqlite3_column_text(stmt, 6);
                if (operation) entry["operation"] = reinterpret_cast<const char*>(operation);
                
                const unsigned char* targetPath = sqlite3_column_text(stmt, 7);
                if (targetPath) entry["target_path"] = reinterpret_cast<const char*>(targetPath);
                
                if (sqlite3_column_type(stmt, 8) != SQLITE_NULL) {
                    entry["success"] = sqlite3_column_int(stmt, 8) ? "Yes" : "No";
                }
                
                const unsigned char* username = sqlite3_column_text(stmt, 9);
                if (username) entry["username"] = reinterpret_cast<const char*>(username);
                
                const unsigned char* additionalInfo = sqlite3_column_text(stmt, 10);
                if (additionalInfo) entry["additional_info"] = reinterpret_cast<const char*>(additionalInfo);
                
                auditEntries.push_back(entry);
            }
            
            sqlite3_finalize(stmt);
            sqlite3_close(db);
            
            // Check if the client accepts HTML
            auto acceptHeader = req->getHeader("Accept");
            if (!acceptHeader.empty() && (acceptHeader.find("text/html") != std::string::npos)) {
                HttpViewData viewData;
                viewData.insert("audit_entries", auditEntries);
                viewData.insert("currentPage", std::string("auditlog"));
                viewData.insert("event_type", eventType);
                viewData.insert("start_date", startDate);
                viewData.insert("end_date", endDate);
                viewData.insert("limit", limit);
                
                auto resp = HttpResponse::newHttpViewResponse("auditlog.csp", viewData);
                callback(resp);
            } else {
                // Return JSON response
                Json::Value root;
                Json::Value entriesArray(Json::arrayValue);
                
                for (const auto& entry : auditEntries) {
                    Json::Value entryObj;
                    for (const auto& [key, value] : entry) {
                        entryObj[key] = value;
                    }
                    entriesArray.append(entryObj);
                }
                
                root["audit_entries"] = entriesArray;
                root["count"] = static_cast<int>(auditEntries.size());
                
                auto resp = HttpResponse::newHttpJsonResponse(root);
                callback(resp);
            }
        });
    }
} // namespace provisioner 