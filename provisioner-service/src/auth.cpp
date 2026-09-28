#include "auth.h"
#include "audit.h"

#include <drogon/drogon.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>
#include <security/pam_appl.h>

#include <arpa/inet.h>
#include <grp.h>
#include <ifaddrs.h>
#include <netinet/in.h>
#include <pwd.h>
#include <unistd.h>

#include <algorithm>
#include <chrono>
#include <cstdlib>
#include <cstring>
#include <mutex>
#include <optional>
#include <set>
#include <thread>
#include <unordered_map>

using namespace drogon;

namespace provisioner {
namespace auth {

namespace {

    using Clock = std::chrono::steady_clock;

    constexpr const char *kSessionCookie = "rpi_sb_session";
    // Deliberately readable by the page's script, which echoes it back in the
    // X-CSRF-Token header. The server compares against the copy held in the
    // session, never against the cookie, so planting a cookie gains nothing.
    constexpr const char *kCsrfCookie = "rpi_sb_csrf";

    constexpr auto kIdleTimeout = std::chrono::hours(2);
    constexpr auto kAbsoluteTimeout = std::chrono::hours(12);
    // How long a membership check is trusted before it is repeated, so removing
    // someone from the group ends their session within a minute.
    constexpr auto kGroupRecheck = std::chrono::seconds(60);
    constexpr size_t kMaxSessions = 256;

    // Every failure takes at least this long, and each address may have only
    // two attempts in flight, which caps guessing at about one a second per
    // address. The wait happens outside the PAM lock, so one address's failures
    // never hold up another's sign-in, and there is no lockout anyone else can
    // trigger.
    constexpr auto kFailureFloor = std::chrono::seconds(2);
    constexpr int kMaxPendingLogins = 16;
    constexpr int kMaxPendingPerPeer = 2;

    struct Session {
        std::string user;
        std::string csrf;
        Clock::time_point created;
        Clock::time_point lastSeen;
        Clock::time_point groupCheckedAt;
    };

    Config g_config;
    std::mutex g_sessionsMutex;
    std::unordered_map<std::string, Session> g_sessions;

    std::mutex g_pamMutex;
    std::mutex g_pendingMutex;
    int g_pendingLogins = 0;
    std::unordered_map<std::string, int> g_pendingByPeer;

    bool admitLogin(const std::string &peer) {
        std::lock_guard<std::mutex> lock(g_pendingMutex);
        if (g_pendingLogins >= kMaxPendingLogins || g_pendingByPeer[peer] >= kMaxPendingPerPeer) return false;
        ++g_pendingLogins;
        ++g_pendingByPeer[peer];
        return true;
    }

    void releaseLogin(const std::string &peer) {
        std::lock_guard<std::mutex> lock(g_pendingMutex);
        --g_pendingLogins;
        if (--g_pendingByPeer[peer] <= 0) g_pendingByPeer.erase(peer);
    }

    // PAM's own failure delay would run inside the lock; ours runs outside it.
    void noPamDelay(int, unsigned, void *) {}

    std::string randomHex(size_t bytes) {
        std::vector<unsigned char> buf(bytes);
        if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) {
            // Without randomness there is no safe session to hand out.
            LOG_FATAL << "RAND_bytes failed; cannot mint session identifiers";
            std::abort();
        }
        static const char *digits = "0123456789abcdef";
        std::string hex;
        hex.reserve(bytes * 2);
        for (unsigned char b : buf) {
            hex.push_back(digits[b >> 4]);
            hex.push_back(digits[b & 0x0f]);
        }
        return hex;
    }

    bool tokensEqual(const std::string &a, const std::string &b) {
        return a.size() == b.size() && !a.empty() &&
               CRYPTO_memcmp(a.data(), b.data(), a.size()) == 0;
    }

    std::string toLower(std::string s) {
        std::transform(s.begin(), s.end(), s.begin(),
                       [](unsigned char c) { return std::tolower(c); });
        return s;
    }

    // "Example.local.:3142" -> "example.local", "[::1]:3142" -> "::1".
    std::string hostOnly(const std::string &authority) {
        std::string host = authority;
        if (!host.empty() && host.front() == '[') {
            const auto close = host.find(']');
            host = close == std::string::npos ? "" : host.substr(1, close - 1);
        } else if (std::count(host.begin(), host.end(), ':') == 1) {
            host = host.substr(0, host.find(':'));
        }
        if (!host.empty() && host.back() == '.') host.pop_back();
        return toLower(host);
    }

    bool isLoopbackPeer(const HttpRequestPtr &req) {
        const std::string ip = req->getPeerAddr().toIp();
        return ip == "127.0.0.1" || ip == "::1" || ip == "::ffff:127.0.0.1";
    }

    // Addresses currently assigned to this machine. An IP literal cannot be
    // rebound by DNS, so any of ours is as safe a Host as "localhost".
    std::set<std::string> localAddresses() {
        static std::mutex mutex;
        static std::set<std::string> cached;
        static Clock::time_point fetched;
        std::lock_guard<std::mutex> lock(mutex);
        if (!cached.empty() && Clock::now() - fetched < std::chrono::seconds(30)) {
            return cached;
        }
        std::set<std::string> found;
        struct ifaddrs *ifs = nullptr;
        if (getifaddrs(&ifs) == 0) {
            for (auto *ifa = ifs; ifa; ifa = ifa->ifa_next) {
                if (!ifa->ifa_addr) continue;
                char buf[INET6_ADDRSTRLEN] = {};
                if (ifa->ifa_addr->sa_family == AF_INET) {
                    inet_ntop(AF_INET, &reinterpret_cast<sockaddr_in *>(ifa->ifa_addr)->sin_addr, buf, sizeof(buf));
                } else if (ifa->ifa_addr->sa_family == AF_INET6) {
                    inet_ntop(AF_INET6, &reinterpret_cast<sockaddr_in6 *>(ifa->ifa_addr)->sin6_addr, buf, sizeof(buf));
                } else {
                    continue;
                }
                found.insert(toLower(buf));
            }
            freeifaddrs(ifs);
        }
        cached = std::move(found);
        fetched = Clock::now();
        return cached;
    }

    bool hostAllowed(const std::string &host) {
        if (host.empty()) return false;
        if (host == "localhost" || host == "127.0.0.1" || host == "::1") return true;

        const std::string listener = toLower(g_config.listenerAddress);
        if (host == listener && listener != "0.0.0.0" && listener != "::") return true;

        char name[256] = {};
        if (gethostname(name, sizeof(name) - 1) == 0) {
            const std::string self = toLower(name);
            if (host == self || host == self + ".local") return true;
        }
        for (const auto &extra : g_config.allowedHosts) {
            if (host == toLower(extra)) return true;
        }
        return localAddresses().count(host) > 0;
    }

    bool inOperatorGroup(const std::string &user) {
        std::vector<char> buf(16384);
        struct group grp {};
        struct group *grpResult = nullptr;
        if (getgrnam_r(kOperatorGroup, &grp, buf.data(), buf.size(), &grpResult) != 0 || !grpResult) {
            return false;
        }
        const gid_t operatorGid = grp.gr_gid;

        struct passwd pw {};
        struct passwd *pwResult = nullptr;
        if (getpwnam_r(user.c_str(), &pw, buf.data(), buf.size(), &pwResult) != 0 || !pwResult) {
            return false;
        }

        int count = 64;
        std::vector<gid_t> groups(count);
        if (getgrouplist(user.c_str(), pw.pw_gid, groups.data(), &count) == -1) {
            groups.resize(count);
            if (getgrouplist(user.c_str(), pw.pw_gid, groups.data(), &count) == -1) {
                return false;
            }
        }
        groups.resize(count);
        return std::find(groups.begin(), groups.end(), operatorGid) != groups.end();
    }

    int pamConversation(int count, const struct pam_message **messages,
                        struct pam_response **responses, void *data) {
        const auto *password = static_cast<const std::string *>(data);
        auto *replies = static_cast<struct pam_response *>(calloc(count, sizeof(struct pam_response)));
        if (!replies) return PAM_BUF_ERR;

        for (int i = 0; i < count; ++i) {
            switch (messages[i]->msg_style) {
                case PAM_PROMPT_ECHO_OFF:
                    replies[i].resp = strdup(password->c_str());
                    if (!replies[i].resp) goto fail;
                    break;
                case PAM_ERROR_MSG:
                case PAM_TEXT_INFO:
                    break;
                default:
                    // A second factor or any other prompt cannot be answered
                    // from a single password form.
                    goto fail;
            }
        }
        *responses = replies;
        return PAM_SUCCESS;

    fail:
        for (int i = 0; i < count; ++i) {
            if (replies[i].resp) {
                OPENSSL_cleanse(replies[i].resp, strlen(replies[i].resp));
                free(replies[i].resp);
            }
        }
        free(replies);
        return PAM_CONV_ERR;
    }

    bool pamAuthenticate(const std::string &user, const std::string &password,
                         const std::string &rhost, std::string &failure) {
        struct pam_conv conv = {pamConversation, const_cast<std::string *>(&password)};
        pam_handle_t *pamh = nullptr;
        int rc = pam_start(kPamService, user.c_str(), &conv, &pamh);
        if (rc != PAM_SUCCESS) {
            failure = "pam_start failed";
            return false;
        }
        pam_set_item(pamh, PAM_RHOST, rhost.c_str());
        pam_set_item(pamh, PAM_FAIL_DELAY, reinterpret_cast<const void *>(&noPamDelay));

        rc = pam_authenticate(pamh, PAM_DISALLOW_NULL_AUTHTOK);
        if (rc == PAM_SUCCESS) {
            rc = pam_acct_mgmt(pamh, PAM_DISALLOW_NULL_AUTHTOK);
        }
        if (rc != PAM_SUCCESS) {
            failure = pam_strerror(pamh, rc);
        }
        pam_end(pamh, rc);
        return rc == PAM_SUCCESS;
    }

    // Only a path on this server, so a crafted link cannot bounce the operator
    // somewhere else after they sign in.
    std::string safeNext(const std::string &next) {
        if (next.empty() || next[0] != '/' || next.rfind("//", 0) == 0 ||
            next.find('\\') != std::string::npos || next.rfind("/login", 0) == 0) {
            return "/devices";
        }
        // Browsers drop tabs and newlines from a URL, so "/\t/host" would
        // become "//host", another site. No control character or space is
        // part of a path worth returning to.
        for (unsigned char c : next) {
            if (c <= 0x20 || c == 0x7f) return "/devices";
        }
        return next;
    }

    // Returns the live session for the request's cookie, refreshing its idle
    // timer, or nullopt. Expired sessions and those whose owner has left the
    // group are removed here.
    std::optional<Session> lookupSession(const HttpRequestPtr &req, std::string *idOut = nullptr) {
        const std::string id = req->getCookie(kSessionCookie);
        if (id.empty()) return std::nullopt;

        std::string user;
        bool recheck = false;
        {
            std::lock_guard<std::mutex> lock(g_sessionsMutex);
            auto it = g_sessions.find(id);
            if (it == g_sessions.end()) return std::nullopt;
            const auto now = Clock::now();
            if (now - it->second.created > kAbsoluteTimeout || now - it->second.lastSeen > kIdleTimeout) {
                g_sessions.erase(it);
                return std::nullopt;
            }
            it->second.lastSeen = now;
            user = it->second.user;
            recheck = now - it->second.groupCheckedAt > kGroupRecheck;
        }

        // NSS may be slow, so check membership outside the lock.
        if (recheck) {
            const bool member = inOperatorGroup(user);
            std::lock_guard<std::mutex> lock(g_sessionsMutex);
            auto it = g_sessions.find(id);
            if (it == g_sessions.end()) return std::nullopt;
            if (!member) {
                LOG_WARN << "SECURITY: ending session for " << user << ", no longer in " << kOperatorGroup;
                g_sessions.erase(it);
                return std::nullopt;
            }
            it->second.groupCheckedAt = Clock::now();
        }

        std::lock_guard<std::mutex> lock(g_sessionsMutex);
        auto it = g_sessions.find(id);
        if (it == g_sessions.end()) return std::nullopt;
        if (idOut) *idOut = id;
        return it->second;
    }

    std::string createSession(const std::string &user, std::string &csrf) {
        std::lock_guard<std::mutex> lock(g_sessionsMutex);
        const auto now = Clock::now();
        for (auto it = g_sessions.begin(); it != g_sessions.end();) {
            if (now - it->second.created > kAbsoluteTimeout || now - it->second.lastSeen > kIdleTimeout) {
                it = g_sessions.erase(it);
            } else {
                ++it;
            }
        }
        if (g_sessions.size() >= kMaxSessions) {
            auto oldest = std::min_element(g_sessions.begin(), g_sessions.end(),
                [](const auto &a, const auto &b) { return a.second.lastSeen < b.second.lastSeen; });
            g_sessions.erase(oldest);
        }
        const std::string id = randomHex(32);
        csrf = randomHex(32);
        g_sessions[id] = Session{user, csrf, now, now, now};
        return id;
    }

    Cookie makeCookie(const HttpRequestPtr &req, const std::string &name,
                      const std::string &value, bool httpOnly, bool expire = false) {
        Cookie cookie(name, value);
        cookie.setPath("/");
        cookie.setHttpOnly(httpOnly);
        cookie.setSecure(req->isOnSecureConnection());
        cookie.setSameSite(Cookie::SameSite::kStrict);
        if (expire) cookie.setMaxAge(0);
        return cookie;
    }

    bool wantsHtml(const HttpRequestPtr &req) {
        return req->getHeader("Accept").find("text/html") != std::string::npos;
    }

    HttpResponsePtr jsonError(HttpStatusCode code, const std::string &error, const std::string &message) {
        Json::Value body;
        body["error"] = error;
        body["message"] = message;
        auto resp = HttpResponse::newHttpJsonResponse(body);
        resp->setStatusCode(code);
        return resp;
    }

    HttpResponsePtr loginPage(const std::string &next, const std::string &error, HttpStatusCode code) {
        HttpViewData data;
        data.insert("next", next);
        data.insert("error", error);
        auto resp = HttpResponse::newHttpViewResponse("login.csp", data);
        resp->setStatusCode(code);
        resp->addHeader("Cache-Control", "no-store");
        return resp;
    }

    // Browsers send Origin on every request that is not a GET or HEAD, and
    // Sec-Fetch-Site on all of them. Either one naming another site means the
    // request was made on some other page's behalf.
    bool originAcceptable(const HttpRequestPtr &req) {
        const std::string fetchSite = req->getHeader("Sec-Fetch-Site");
        if (!fetchSite.empty() && fetchSite != "same-origin" && fetchSite != "none") {
            return false;
        }
        const std::string origin = req->getHeader("Origin");
        if (origin.empty()) {
            // Not a browser; the CSRF token still has to match.
            return true;
        }
        const auto scheme = origin.find("://");
        if (scheme == std::string::npos) return false;
        return toLower(origin.substr(scheme + 3)) == toLower(req->getHeader("Host"));
    }

    bool isStateChanging(const HttpRequestPtr &req) {
        const auto method = req->method();
        return method != Get && method != Head;
    }

    // A WebSocket handshake is a GET, but it is not bound by CORS: any page may
    // open one and read everything that comes back.
    bool isWebSocket(const HttpRequestPtr &req) {
        return toLower(req->getHeader("Upgrade")) == "websocket";
    }

    void handleLogin(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
        const std::string next = safeNext(req->getParameter("next"));

        if (req->method() != Post) {
            if (lookupSession(req)) {
                auto resp = HttpResponse::newRedirectionResponse(next, k303SeeOther);
                callback(resp);
                return;
            }
            callback(loginPage(next, "", k200OK));
            return;
        }

        if (g_config.requireTlsForRemoteLogin && !req->isOnSecureConnection() && !isLoopbackPeer(req)) {
            callback(loginPage(next, "Sign in over HTTPS: this connection is not encrypted.", k403Forbidden));
            return;
        }

        std::string user = req->getParameter("username");
        std::string password = req->getParameter("password");
        if (user.empty() || password.empty() || user.size() > 256 || password.size() > 1024) {
            OPENSSL_cleanse(password.data(), password.size());
            callback(loginPage(next, "Enter a username and password.", k400BadRequest));
            return;
        }

        // Proxy-aware, so operators behind a reverse proxy are not one address.
        const std::string rhost = AuditLog::getClientIP(req);
        if (!admitLogin(rhost)) {
            OPENSSL_cleanse(password.data(), password.size());
            callback(loginPage(next, "Too many sign-in attempts in progress. Try again shortly.", k429TooManyRequests));
            return;
        }

        // PAM blocks, and failures are slowed, so keep it off the event loop.
        std::thread([req, user = std::move(user), password = std::move(password), rhost, next,
                     callback = std::move(callback)]() mutable {
            std::string failure;
            bool ok;
            const auto started = Clock::now();
            {
                std::lock_guard<std::mutex> lock(g_pamMutex);
                ok = pamAuthenticate(user, password, rhost, failure);
            }
            if (ok && !inOperatorGroup(user)) {
                ok = false;
                failure = std::string("not a member of ") + kOperatorGroup;
            }
            if (!ok) std::this_thread::sleep_until(started + kFailureFloor);
            OPENSSL_cleanse(password.data(), password.size());
            releaseLogin(rhost);

            AuditLog::logAuthentication(req, user, "LOGIN", ok, failure);
            if (!ok) {
                LOG_WARN << "SECURITY: sign-in refused for " << user << " from " << rhost << ": " << failure;
                // One message for every cause, so the form does not reveal
                // which accounts exist or who is an operator.
                callback(loginPage(next, "Sign-in failed. Check the username and password, "
                                         "and that the account is in the rpi-sb-provisioner group.",
                                   k401Unauthorized));
                return;
            }

            LOG_INFO << "SECURITY: " << user << " signed in from " << rhost;
            std::string csrf;
            const std::string id = createSession(user, csrf);
            auto resp = HttpResponse::newRedirectionResponse(next, k303SeeOther);
            resp->addCookie(makeCookie(req, kSessionCookie, id, true));
            resp->addCookie(makeCookie(req, kCsrfCookie, csrf, false));
            callback(resp);
        }).detach();
    }

    void handleLogout(const HttpRequestPtr &req, std::function<void(const HttpResponsePtr &)> &&callback) {
        std::string id;
        if (auto session = lookupSession(req, &id)) {
            AuditLog::logAuthentication(req, session->user, "LOGOUT", true, "");
            std::lock_guard<std::mutex> lock(g_sessionsMutex);
            g_sessions.erase(id);
        }
        auto resp = HttpResponse::newRedirectionResponse("/login", k303SeeOther);
        resp->addCookie(makeCookie(req, kSessionCookie, "", true, true));
        resp->addCookie(makeCookie(req, kCsrfCookie, "", false, true));
        callback(resp);
    }

} // namespace

    std::string csrfToken(const HttpRequestPtr &req) {
        return req->attributes()->get<std::string>("auth.csrf");
    }

    std::string username(const HttpRequestPtr &req) {
        return req->attributes()->get<std::string>("auth.user");
    }

    void install(HttpAppFramework &app, Config config) {
        g_config = std::move(config);

        app.registerPreRoutingAdvice([](const HttpRequestPtr &req, AdviceCallback &&stop, AdviceChainCallback &&pass) {
            // A name we do not answer to is a DNS rebinding attempt or a
            // misconfigured proxy. Either way, nothing here is for it.
            if (!hostAllowed(hostOnly(req->getHeader("Host")))) {
                LOG_WARN << "SECURITY: refused request for unrecognised Host '" << req->getHeader("Host")
                         << "' from " << req->getPeerAddr().toIp();
                auto resp = HttpResponse::newHttpResponse();
                resp->setStatusCode(k421MisdirectedRequest);
                resp->setContentTypeCode(CT_TEXT_PLAIN);
                resp->setBody("Unrecognised host name. Start rpi-provisioner-ui with --allowed-host to add one.\n");
                stop(resp);
                return;
            }

            const std::string &path = req->path();

            // Called by the provisioning scripts, which authenticate with the
            // root-only token in /run/rpi-sb-provisioner instead.
            if (path.rfind("/internal/", 0) == 0) {
                pass();
                return;
            }

            if ((isStateChanging(req) || isWebSocket(req)) && !originAcceptable(req)) {
                LOG_WARN << "SECURITY: refused cross-origin " << req->getMethodString() << " " << path
                         << " (Origin '" << req->getHeader("Origin") << "')";
                stop(jsonError(k403Forbidden, "CROSS_ORIGIN", "Cross-origin requests are not accepted."));
                return;
            }

            if (path == "/login" || path.rfind("/static/", 0) == 0) {
                pass();
                return;
            }

            auto session = lookupSession(req);
            if (!session) {
                if (!isStateChanging(req) && wantsHtml(req)) {
                    std::string next = path;
                    if (!req->query().empty()) next += "?" + req->query();
                    stop(HttpResponse::newRedirectionResponse(
                        "/login?next=" + drogon::utils::urlEncodeComponent(next), k303SeeOther));
                } else {
                    stop(jsonError(k401Unauthorized, "UNAUTHENTICATED", "Sign in to use the provisioner."));
                }
                return;
            }

            if (isStateChanging(req)) {
                std::string presented = req->getHeader("X-CSRF-Token");
                if (presented.empty()) presented = req->getParameter("_csrf_token");
                if (!tokensEqual(presented, session->csrf)) {
                    LOG_WARN << "SECURITY: CSRF token mismatch for " << req->getMethodString() << " " << path
                             << " from " << AuditLog::getClientIP(req);
                    stop(jsonError(k403Forbidden, "CSRF_VALIDATION_FAILED",
                                   "Invalid or expired security token. Please refresh the page and try again."));
                    return;
                }
            }

            req->attributes()->insert("auth.user", session->user);
            req->attributes()->insert("auth.csrf", session->csrf);
            pass();
        });

        app.registerHandler("/login", &handleLogin, {Get, Post});
        app.registerHandler("/logout", &handleLogout, {Post});
        app.registerHandler("/auth/session", [](const HttpRequestPtr &req,
                                                std::function<void(const HttpResponsePtr &)> &&callback) {
            Json::Value body;
            body["user"] = username(req);
            body["csrfToken"] = csrfToken(req);
            auto resp = HttpResponse::newHttpJsonResponse(body);
            resp->addHeader("Cache-Control", "no-store");
            callback(resp);
        }, {Get});
    }

} // namespace auth
} // namespace provisioner
