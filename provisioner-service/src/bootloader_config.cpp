#include "include/bootloader_config.h"

#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <regex>
#include <set>
#include <sstream>

#include <drogon/HttpAppFramework.h>
#include <json/json.h>

#include "include/audit.h"
#include "include/auth.h"
#include "utils.h"

namespace provisioner {
namespace {

    const std::string kEdited = "/etc/rpi-sb-provisioner/bootloader.";
    const std::string kDefault = "/var/lib/rpi-sb-provisioner/bootloader.";
    const std::string kHelp = "/usr/share/rpi-sb-provisioner/static/js/bootloader-help.json";
    // rpi-eeprom-config's MAX_FILE_SIZE: a 4 KiB erase block less its header.
    constexpr size_t kMaxBytes = 4076;
    // Far more than any real configuration, so a request cannot make us work.
    constexpr size_t kMaxRequest = 64 * 1024;

    bool validKind(const std::string &kind) { return kind == "secure" || kind == "naked"; }

    std::optional<std::string> readFile(const std::string &path) {
        std::ifstream f(path, std::ios::binary);
        if (!f.is_open()) return std::nullopt;
        std::stringstream s;
        s << f.rdbuf();
        return s.str();
    }

    // The settings the documentation describes, from the help the editor shows.
    const std::set<std::string> &knownSettings() {
        static std::once_flag once;
        static std::set<std::string> names;
        std::call_once(once, [] {
            auto text = readFile(kHelp);
            Json::Value doc;
            Json::CharReaderBuilder builder;
            std::string errors;
            std::istringstream in(text.value_or(""));
            if (text && Json::parseFromStream(builder, in, &doc, &errors) && doc["settings"].isObject()) {
                for (const auto &name : doc["settings"].getMemberNames()) names.insert(name);
            } else {
                LOG_WARN << "Bootloader help not readable at " << kHelp << "; unknown settings go unreported";
            }
        });
        return names;
    }

    struct Findings {
        Json::Value errors{Json::arrayValue};
        Json::Value warnings{Json::arrayValue};
        size_t bytes = 0;
    };

    void add(Json::Value &list, int line, const std::string &message) {
        Json::Value f;
        f["line"] = line;
        f["message"] = message;
        list.append(f);
    }

    // What bootstrap and rpi-eeprom-config will make of the text.
    Findings check(const std::string &kind, const std::string &text) {
        Findings out;
        static const std::regex setting(R"(^([A-Za-z0-9_]+)=(.*)$)");
        static const std::regex hex(R"(^0[xX][0-9a-fA-F]{1,8}$)");
        bool signedBoot = false;
        std::istringstream in(text);
        std::string line;
        int n = 0;
        while (std::getline(in, line)) {
            ++n;
            const bool plain = std::all_of(line.begin(), line.end(), [](unsigned char c) {
                return c == '\t' || (c >= 0x20 && c < 0x7f);
            });
            if (!plain) {
                add(out.errors, n, "Only plain ASCII text: this line has a control or non-ASCII character");
                continue;
            }
            const auto start = line.find_first_not_of(" \t");
            if (start == std::string::npos || line[start] == '#') continue;
            const std::string body = line.substr(start, line.find_last_not_of(" \t") - start + 1);
            if (body.front() == '[') {
                if (body.back() != ']') add(out.errors, n, "A filter must be closed, as in [pi5]");
                continue;
            }
            std::smatch m;
            if (!std::regex_match(body, m, setting)) {
                add(out.errors, n, "Not a setting (NAME=value), a [filter] or a # comment");
                continue;
            }
            const std::string name = m[1], value = m[2];
            if (!knownSettings().empty() && !knownSettings().count(name)) {
                add(out.warnings, n, name + " is not a setting the Raspberry Pi documentation describes");
            }
            if (name == "BOOT_ORDER" && !std::regex_match(value, hex)) {
                add(out.errors, n, "BOOT_ORDER is a hexadecimal number of up to eight digits, such as 0xf41");
            }
            if (name == "SIGNED_BOOT") {
                if (value == "1") signedBoot = true;
                else if (kind == "secure") add(out.warnings, n, "Secure boot always uses SIGNED_BOOT=1; this line is replaced");
            }
        }
        // Bootstrap ends the file with a newline and, for secure boot, adds SIGNED_BOOT=1.
        out.bytes = text.size() + ((!text.empty() && text.back() != '\n') ? 1 : 0) +
                    ((kind == "secure" && !signedBoot) ? std::string("SIGNED_BOOT=1\n").size() : 0);
        if (out.bytes > kMaxBytes) {
            add(out.errors, 0, "The configuration comes to " + std::to_string(out.bytes) +
                                " bytes on the device; the EEPROM holds at most " + std::to_string(kMaxBytes));
        }
        return out;
    }

    bool writeAtomically(const std::string &path, const std::string &data) {
        const std::string tmp = path + ".tmp";
        ::unlink(tmp.c_str());
        const int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC, 0644);
        if (fd < 0) return false;
        bool ok = ::fchmod(fd, 0644) == 0;
        for (size_t done = 0; ok && done < data.size();) {
            const ssize_t w = ::write(fd, data.data() + done, data.size() - done);
            if (w <= 0) ok = false; else done += static_cast<size_t>(w);
        }
        ok = ok && ::fsync(fd) == 0;
        ok = (::close(fd) == 0) && ok;
        if (!ok || ::rename(tmp.c_str(), path.c_str()) != 0) {
            ::unlink(tmp.c_str());
            return false;
        }
        return true;
    }

    HttpResponsePtr json(const Json::Value &body, HttpStatusCode code = k200OK) {
        auto resp = HttpResponse::newHttpJsonResponse(body);
        resp->setStatusCode(code);
        return resp;
    }

    Json::Value findingsJson(const Findings &f) {
        Json::Value v;
        v["errors"] = f.errors;
        v["warnings"] = f.warnings;
        v["bytes"] = static_cast<Json::UInt64>(f.bytes);
        v["max_bytes"] = static_cast<Json::UInt64>(kMaxBytes);
        return v;
    }

    // A JSON body with a valid kind and, if wanted, content of a sane size.
    bool readRequest(const HttpRequestPtr &req, bool needContent, std::string &kind, std::string &content,
                     HttpResponsePtr &error) {
        auto body = req->getJsonObject();
        if (!body || !(*body)["kind"].isString() || !validKind((*body)["kind"].asString()) ||
            (needContent && !(*body)["content"].isString())) {
            error = utils::createErrorResponse(req, "Give kind (secure or naked) and content",
                                               k400BadRequest, "Invalid Request", "INVALID_REQUEST");
            return false;
        }
        kind = (*body)["kind"].asString();
        content = needContent ? (*body)["content"].asString() : "";
        if (content.size() > kMaxRequest) {
            error = utils::createErrorResponse(req, "The configuration is far too large", k413RequestEntityTooLarge,
                                               "Too Large", "TOO_LARGE");
            return false;
        }
        return true;
    }

} // namespace

void BootloaderConfig::registerHandlers(HttpAppFramework &app) {
    app.registerHandler("/options/bootloader-config", [](const HttpRequestPtr &req,
                                                        std::function<void(const HttpResponsePtr &)> &&callback) {
        AuditLog::logHandlerAccess(req, "/options/bootloader-config");
        std::string kind = req->getParameter("kind");
        if (!validKind(kind)) kind = "secure";
        const auto edited = readFile(kEdited + kind);
        const auto config = utils::getAllConfigValues();
        const auto explicitIt = config.find("RPI_DEVICE_BOOTLOADER_CONFIG_FILE");
        HttpViewData data;
        data.insert("currentPage", std::string("options"));
        data.insert("kind", kind);
        data.insert("content", edited.value_or(readFile(kDefault + kind).value_or("")));
        data.insert("edited", edited.has_value());
        data.insert("explicit_path", explicitIt != config.end() ? explicitIt->second : std::string());
        data.insert("max_bytes", std::to_string(kMaxBytes));
        callback(HttpResponse::newHttpViewResponse("bootloader_config.csp", data));
    }, {Get});

    // The help, from the documentation shipped in the package. Static files
    // are served by type, and JSON is not among them.
    app.registerHandler("/options/bootloader-config/help", [](const HttpRequestPtr &,
                                                             std::function<void(const HttpResponsePtr &)> &&callback) {
        auto resp = HttpResponse::newHttpResponse();
        const auto text = readFile(kHelp);
        resp->setStatusCode(text ? k200OK : k404NotFound);
        resp->setContentTypeCode(CT_APPLICATION_JSON);
        resp->setBody(text.value_or("{\"settings\": {}}"));
        callback(resp);
    }, {Get});

    app.registerHandler("/options/bootloader-config/check", [](const HttpRequestPtr &req,
                                                              std::function<void(const HttpResponsePtr &)> &&callback) {
        std::string kind, content;
        HttpResponsePtr error;
        if (!readRequest(req, true, kind, content, error)) return callback(error);
        callback(json(findingsJson(check(kind, content))));
    }, {Post});

    app.registerHandler("/options/bootloader-config/save", [](const HttpRequestPtr &req,
                                                             std::function<void(const HttpResponsePtr &)> &&callback) {
        std::string kind, content;
        HttpResponsePtr error;
        if (!readRequest(req, true, kind, content, error)) return callback(error);
        const Findings found = check(kind, content);
        Json::Value body = findingsJson(found);
        if (!found.errors.empty()) {
            body["saved"] = false;
            return callback(json(body, k400BadRequest));
        }
        if (!content.empty() && content.back() != '\n') content += '\n';
        const std::string path = kEdited + kind;
        const bool ok = writeAtomically(path, content);
        AuditLog::logFileSystemAccess("BOOTLOADER_CONFIG_SAVE", path, ok, auth::username(req));
        if (!ok) {
            return callback(utils::createErrorResponse(req, "Could not write " + path, k500InternalServerError,
                                                       "Write Error", "WRITE_ERROR", std::strerror(errno)));
        }
        body["saved"] = true;
        callback(json(body));
    }, {Post});

    app.registerHandler("/options/bootloader-config/reset", [](const HttpRequestPtr &req,
                                                              std::function<void(const HttpResponsePtr &)> &&callback) {
        std::string kind, content;
        HttpResponsePtr error;
        if (!readRequest(req, false, kind, content, error)) return callback(error);
        const std::string path = kEdited + kind;
        std::error_code ec;
        std::filesystem::remove(path, ec);
        AuditLog::logFileSystemAccess("BOOTLOADER_CONFIG_RESET", path, !ec, auth::username(req));
        if (ec) {
            return callback(utils::createErrorResponse(req, "Could not remove " + path, k500InternalServerError,
                                                       "Write Error", "WRITE_ERROR", ec.message()));
        }
        Json::Value body;
        body["content"] = readFile(kDefault + kind).value_or("");
        callback(json(body));
    }, {Post});
}

} // namespace provisioner
