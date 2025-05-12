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
    };
} // namespace provisioner 