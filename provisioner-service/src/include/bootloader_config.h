#pragma once

#include <drogon/HttpAppFramework.h>

using namespace drogon;

namespace provisioner {
// The bootloader configuration editor: one file per kind of device, secure
// boot or not, kept in /etc/rpi-sb-provisioner and signed into the EEPROM.
class BootloaderConfig {
    public:
        void registerHandlers(HttpAppFramework &app);
    };
} // namespace provisioner
