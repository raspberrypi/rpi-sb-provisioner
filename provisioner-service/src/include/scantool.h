#pragma once

#include <drogon/HttpAppFramework.h>

using namespace drogon;

namespace provisioner {
    class ScanTool {
    public:
        ScanTool();
        ~ScanTool();

        void registerHandlers(HttpAppFramework &app);
    };
} // namespace provisioner 