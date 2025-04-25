#pragma once

#include <drogon/HttpAppFramework.h>
#include <sqlite3.h>
#include <mutex>
#include <string>
#include <memory>

using namespace drogon;

namespace provisioner {
    class AuditLog {
    public:
        AuditLog();
        ~AuditLog();

        // Register the web handlers for the audit log page
        void registerHandlers(HttpAppFramework &app);
        
        // Log a handler access with client information
        static void logHandlerAccess(const HttpRequestPtr &req, const std::string &handlerPath);
        
        // Log file system access or modification
        static void logFileSystemAccess(const std::string &operation, const std::string &path, 
                                       bool success, const std::string &username = "",
                                       const std::string &additional_info = "");
        
        // Log systemd log access
        static void logSystemdAccess(const std::string &service, const std::string &username = "");

    private:
        static bool ensureAuditDatabase();
        static std::string getClientIP(const HttpRequestPtr &req);
        
        // Database path
        static const std::string AUDIT_DB_PATH;
        
        // Thread safety for database operations
        static std::mutex dbMutex;
    };
} // namespace provisioner 