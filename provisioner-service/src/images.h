#pragma once

#include <drogon/drogon.h>
#include <drogon/HttpAppFramework.h>
#include <drogon/HttpResponse.h>
#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <memory>
#include <future>

namespace provisioner {

    // Export cache and calculation functions for WebSocket controller
    extern std::unordered_map<std::string, std::string> sha256Cache;
    extern std::mutex sha256Cache_mutex;
    
    // Function to start SHA256 calculation asynchronously
    std::shared_ptr<std::future<std::string>> startSHA256Calculation(const std::string& imageName);

    struct ImageInfo {
        std::string name;
        std::string sha256;
    };

    class Images {
    public:
        Images();
        ~Images();

        void registerHandlers(drogon::HttpAppFramework &app);
    };

} // namespace provisioner 