#pragma once

#include <drogon/HttpAppFramework.h>

using namespace drogon;

namespace provisioner {
    struct ServiceInfo {
        std::string name;        // Service name with @ (e.g. rpi-sb-bootstrap@)
        std::string status;      // Current status
        std::string active;      // Active state
        std::string instance;    // For template instance services (after @)
        std::string base_name;   // Base name without @ for grouping
    };

    class Services {
    public:
        Services();
        ~Services();
        void registerHandlers(drogon::HttpAppFramework &app);
    };
} // namespace provisioner 