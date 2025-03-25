#pragma once

#include <drogon/HttpAppFramework.h>

using namespace drogon;

namespace provisioner {
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
