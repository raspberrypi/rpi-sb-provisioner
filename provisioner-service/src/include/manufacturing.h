#pragma once

#include <drogon/HttpAppFramework.h>
#include <vector>
#include <map>
#include <string>
#include <utility>

using namespace drogon;

namespace provisioner {
    class Manufacturing {
    public:
        Manufacturing();
        ~Manufacturing();

        void registerHandlers(HttpAppFramework &app);
        
    private:
        // Helper method to retrieve manufacturing devices with optional pagination
        std::pair<bool, std::vector<std::map<std::string, std::string>>> getManufacturingDevices(
            const HttpRequestPtr &req, 
            int offset = 0, 
            int limit = -1);
    };
} // namespace provisioner 