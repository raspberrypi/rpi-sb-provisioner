#pragma once

#include <drogon/HttpAppFramework.h>

using namespace drogon;

namespace provisioner {
    class Manufacturing {
    public:
        Manufacturing();
        ~Manufacturing();

        void registerHandlers(HttpAppFramework &app);
    };
} // namespace provisioner 