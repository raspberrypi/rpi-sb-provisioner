#pragma once

#include <drogon/HttpAppFramework.h>

using namespace drogon;

namespace provisioner {
class Customisation {
    public:
        Customisation();
        ~Customisation();
        void registerHandlers(HttpAppFramework &app);
    private:
        
    };
} // namespace provisioner
