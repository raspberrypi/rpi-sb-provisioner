#pragma once

#include <drogon/HttpAppFramework.h>

using namespace drogon;

namespace provisioner {
    struct ServiceInfo {
        std::string name;
        std::string status;
        std::string active;
    };

    class Services {
    public:
        Services();
        ~Services();
        void registerHandlers(drogon::HttpAppFramework &app);
    };
} // namespace provisioner 