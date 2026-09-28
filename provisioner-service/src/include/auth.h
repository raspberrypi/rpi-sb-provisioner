#pragma once

#include <drogon/HttpAppFramework.h>

#include <string>
#include <vector>

namespace provisioner {
namespace auth {

    // Members of this group may sign in to the web UI. Membership is what makes
    // someone an operator: the UI runs as root and everything it exposes, from
    // customisation hooks to OTP writes, is root-equivalent.
    inline constexpr const char *kOperatorGroup = "rpi-sb-provisioner";

    // PAM service name, i.e. the file in /etc/pam.d.
    inline constexpr const char *kPamService = "rpi-provisioner-ui";

    struct Config {
        // The address the HTTP and HTTPS listeners are bound to.
        std::string listenerAddress;
        // Extra names the UI may be reached by, such as a reverse proxy's
        // public name. Checked against Host and Origin.
        std::vector<std::string> allowedHosts;
        // Refuse a sign-in over plain HTTP from anything but loopback, since
        // the password would cross the network in the clear.
        bool requireTlsForRemoteLogin = false;
    };

    // Registers /login, /logout and /auth/session, and the pre-routing gate
    // that every other request passes through. Call before any other handler
    // is registered.
    void install(drogon::HttpAppFramework &app, Config config);

    // The CSRF token bound to the request's session, or empty when there is no
    // session. The gate has already checked it on every state-changing request.
    std::string csrfToken(const drogon::HttpRequestPtr &req);

    // The signed-in operator, or empty.
    std::string username(const drogon::HttpRequestPtr &req);

} // namespace auth
} // namespace provisioner
