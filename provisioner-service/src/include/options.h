#pragma once

#include <drogon/HttpAppFramework.h>

using namespace drogon;

namespace provisioner {
class Options {
    public:
        Options();
        ~Options();
        void registerHandlers(HttpAppFramework &app);
    };
} // namespace provisioner