#include <drogon/drogon.h>
#include <netinet/tcp.h>
#include <filesystem>

#include "images.h"
#include "devices.h"
#include "customisation.h"
#include "options.h"
#include "services.h"
#include "manufacturing.h"

using namespace drogon;

int main()
{
    auto nthreads = std::thread::hardware_concurrency();
    if (nthreads == 0) nthreads = 1;

    provisioner::Images imageHandlers = {};
    provisioner::Devices deviceHandlers = {};
    provisioner::Customisation customisationHandlers = {};
    provisioner::Options optionHandlers = {};
    provisioner::Services serviceHandlers = {};
    provisioner::Manufacturing manufacturingHandlers = {};

    auto& app = HttpAppFramework::instance();

    imageHandlers.registerHandlers(app);
    deviceHandlers.registerHandlers(app);
    customisationHandlers.registerHandlers(app);
    optionHandlers.registerHandlers(app);
    serviceHandlers.registerHandlers(app);
    manufacturingHandlers.registerHandlers(app);

    // Register root path handler to redirect to devices
    app.registerHandler("/", [](const drogon::HttpRequestPtr &req, std::function<void(const drogon::HttpResponsePtr &)> &&callback) {
        auto resp = drogon::HttpResponse::newHttpResponse();
        resp->setStatusCode(drogon::k302Found);
        resp->addHeader("Location", "/devices");
        callback(resp);
    });

    // Get the current executable path and use it to calculate the static files path
    std::filesystem::path execPath = std::filesystem::current_path();
    std::string staticPath = (execPath / "provisioner-service/src/static").string();
    constexpr const char *uploadPath = "/srv/rpi-sb-provisioner/uploads";

    if (!std::filesystem::exists(uploadPath)) {
        std::filesystem::create_directories(uploadPath);
    }
    
    app
    .setBeforeListenSockOptCallback([](int fd) {
        LOG_INFO << "setBeforeListenSockOptCallback:" << fd;

        int enable = 1;
        if (setsockopt(
                fd, IPPROTO_TCP, TCP_FASTOPEN, &enable, sizeof(enable)) ==
            -1)
        {
            LOG_INFO << "setsockopt TCP_FASTOPEN failed";
        }
    })
    .setLogLevel(trantor::Logger::kTrace)
    .addListener("0.0.0.0", 3142)
    .setClientMaxBodySize(std::numeric_limits<size_t>::max())
    .setThreadNum(nthreads)
    .setDocumentRoot(staticPath)
    .setUploadPath(uploadPath)
    .setStaticFilesCacheTime(0) // Disable caching during development
    //.enableRunAsDaemon()
    .run();
}