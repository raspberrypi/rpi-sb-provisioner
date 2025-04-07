#include <drogon/drogon.h>
#include <netinet/tcp.h>
#include <filesystem>
#include <cstdio>
#include <memory>
#include <regex>

#include "images.h"
#include "devices.h"
#include "customisation.h"
#include "options.h"
#include <services.h>
#include "manufacturing.h"

using namespace drogon;

// Function to get the current package version
std::string getPackageVersion() {
    std::string version = "unknown";
    
    FILE* pipe = popen("dpkg-query -f='${Version}' -W rpi-sb-provisioner 2>/dev/null", "r");
    if (pipe) {
        char buffer[128];
        if (fgets(buffer, sizeof(buffer), pipe)) {
            version = buffer;
            // Trim any newlines
            if (!version.empty() && version.back() == '\n') {
                version.pop_back();
            }
        }
        pclose(pipe);
    }
    
    return version;
}

// Function to check for newer GitHub releases
struct VersionInfo {
    std::string latest;
    bool has_newer;
    std::string release_url;
};

VersionInfo checkForNewerRelease(const std::string& current_version) {
    VersionInfo info = {"", false, ""};
    
    // Use curl to fetch the latest release from GitHub API
    FILE* pipe = popen("curl -s https://api.github.com/repos/raspberrypi/rpi-sb-provisioner/releases/latest | grep '\"tag_name\"\\|\"html_url\"' | head -2", "r");
    if (!pipe) return info;
    
    std::string tag_name, html_url;
    char buffer[512];
    
    while (fgets(buffer, sizeof(buffer), pipe)) {
        std::string line(buffer);
        
        if (line.find("tag_name") != std::string::npos) {
            std::regex tag_regex("\"tag_name\":\\s*\"([^\"]+)\"");
            std::smatch matches;
            if (std::regex_search(line, matches, tag_regex) && matches.size() > 1) {
                tag_name = matches[1].str();
                // Remove 'v' prefix if present
                if (!tag_name.empty() && tag_name[0] == 'v') {
                    tag_name = tag_name.substr(1);
                }
            }
        }
        
        if (line.find("html_url") != std::string::npos) {
            std::regex url_regex("\"html_url\":\\s*\"([^\"]+)\"");
            std::smatch matches;
            if (std::regex_search(line, matches, url_regex) && matches.size() > 1) {
                html_url = matches[1].str();
            }
        }
    }
    
    pclose(pipe);
    
    info.latest = tag_name;
    info.release_url = html_url;
    
    // Compare versions (simple string comparison - assuming versions are in compatible format)
    // For more complex version comparison, a dedicated version comparison function would be needed
    if (!tag_name.empty() && !current_version.empty() && tag_name != current_version) {
        info.has_newer = tag_name > current_version;
    }
    
    return info;
}

// Global variables that will be accessed by views
std::string g_packageVersion;
bool g_hasNewerVersion = false;
std::string g_releaseUrl;

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

    // Get package version and set it as a global value
    g_packageVersion = getPackageVersion();
    
    // Check for newer GitHub releases
    VersionInfo versionInfo = checkForNewerRelease(g_packageVersion);
    g_hasNewerVersion = versionInfo.has_newer;
    g_releaseUrl = versionInfo.release_url;

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

    // Configure upload path
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
    .addListener("127.0.0.1", 3142)
    .setClientMaxBodySize(std::numeric_limits<size_t>::max())
    .setThreadNum(nthreads)
    .setUploadPath(uploadPath)
    //.enableRunAsDaemon()
    .run();
}