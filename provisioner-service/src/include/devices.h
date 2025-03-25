#pragma once

#include <drogon/HttpAppFramework.h>
#include <systemd/sd-bus.h>

using namespace drogon;

namespace provisioner {
class Devices {
    public:
        Devices();
        ~Devices();
        void registerHandlers(HttpAppFramework &app);
    private:
        std::unique_ptr<sd_bus, decltype(&sd_bus_unref)> systemd_bus;
    };
} // namespace provisioner
