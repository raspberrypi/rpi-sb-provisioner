#include "api_tokens.h"

#include <drogon/drogon.h>
#include <json/json.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

#include <ctime>
#include <filesystem>
#include <fstream>
#include <mutex>
#include <sstream>

namespace provisioner {
namespace auth {
namespace tokens {

namespace {

    constexpr const char *kPrefix = "rpisb_";
    constexpr size_t kMaxTokens = 64;

    struct Stored {
        TokenInfo info;
        std::string hash;
    };

    std::mutex g_mutex;
    bool g_loaded = false;
    std::vector<Stored> g_tokens;

    std::string hex(const unsigned char *data, size_t len) {
        static const char *digits = "0123456789abcdef";
        std::string out;
        out.reserve(len * 2);
        for (size_t i = 0; i < len; ++i) {
            out.push_back(digits[data[i] >> 4]);
            out.push_back(digits[data[i] & 0x0f]);
        }
        return out;
    }

    std::string randomHex(size_t bytes) {
        std::vector<unsigned char> buf(bytes);
        if (RAND_bytes(buf.data(), static_cast<int>(buf.size())) != 1) return "";
        return hex(buf.data(), buf.size());
    }

    std::string sha256(const std::string &data) {
        unsigned char digest[EVP_MAX_MD_SIZE];
        unsigned int len = 0;
        EVP_Digest(data.data(), data.size(), digest, &len, EVP_sha256(), nullptr);
        return hex(digest, len);
    }

    // Caller holds g_mutex.
    void loadLocked() {
        if (g_loaded) return;
        g_loaded = true;
        std::ifstream in(kStorePath);
        if (!in) return;
        Json::Value root;
        Json::CharReaderBuilder builder;
        std::string errs;
        if (!Json::parseFromStream(builder, in, &root, &errs) || !root.isArray()) {
            LOG_ERROR << "Ignoring unreadable API token store " << kStorePath << ": " << errs;
            return;
        }
        for (const auto &t : root) {
            Stored s;
            s.info.id = t["id"].asString();
            s.info.user = t["user"].asString();
            s.info.label = t["label"].asString();
            s.info.created = t["created"].asString();
            s.hash = t["sha256"].asString();
            if (!s.info.id.empty() && s.hash.size() == 64) g_tokens.push_back(std::move(s));
        }
    }

    // Caller holds g_mutex. Written to a 0600 temporary and renamed, so the
    // store is never briefly readable or half-written.
    bool saveLocked() {
        Json::Value root(Json::arrayValue);
        for (const auto &s : g_tokens) {
            Json::Value t;
            t["id"] = s.info.id;
            t["user"] = s.info.user;
            t["label"] = s.info.label;
            t["created"] = s.info.created;
            t["sha256"] = s.hash;
            root.append(t);
        }
        Json::StreamWriterBuilder writer;
        const std::string body = Json::writeString(writer, root) + "\n";

        std::error_code ec;
        std::filesystem::create_directories(std::filesystem::path(kStorePath).parent_path(), ec);
        const std::string tmp = std::string(kStorePath) + ".tmp";
        const int fd = open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC, 0600);
        if (fd < 0) return false;
        bool ok = fchmod(fd, 0600) == 0 &&
                  write(fd, body.data(), body.size()) == static_cast<ssize_t>(body.size()) &&
                  fsync(fd) == 0;
        ok = close(fd) == 0 && ok;
        if (!ok || rename(tmp.c_str(), kStorePath) != 0) {
            unlink(tmp.c_str());
            return false;
        }
        return true;
    }

    std::string nowIso() {
        std::time_t now = std::time(nullptr);
        std::tm tm {};
        gmtime_r(&now, &tm);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return buf;
    }

} // namespace

    std::optional<Created> create(const std::string &user, const std::string &label, std::string &error) {
        std::lock_guard<std::mutex> lock(g_mutex);
        loadLocked();
        if (g_tokens.size() >= kMaxTokens) {
            error = "Too many API tokens; revoke one first.";
            return std::nullopt;
        }
        const std::string random = randomHex(32);
        const std::string id = randomHex(4);
        if (random.empty() || id.empty()) {
            error = "Could not generate a token.";
            return std::nullopt;
        }
        Created created{{id, user, label, nowIso()}, kPrefix + random};
        g_tokens.push_back(Stored{created.info, sha256(created.secret)});
        if (!saveLocked()) {
            g_tokens.pop_back();
            error = "Could not save the token store.";
            return std::nullopt;
        }
        return created;
    }

    bool revoke(const std::string &id, std::string &revokedOwner) {
        std::lock_guard<std::mutex> lock(g_mutex);
        loadLocked();
        for (auto it = g_tokens.begin(); it != g_tokens.end(); ++it) {
            if (it->info.id == id) {
                Stored removed = *it;
                g_tokens.erase(it);
                if (!saveLocked()) {
                    g_tokens.push_back(std::move(removed));
                    return false;
                }
                revokedOwner = removed.info.user;
                return true;
            }
        }
        return false;
    }

    std::vector<TokenInfo> list() {
        std::lock_guard<std::mutex> lock(g_mutex);
        loadLocked();
        std::vector<TokenInfo> out;
        for (const auto &s : g_tokens) out.push_back(s.info);
        return out;
    }

    std::optional<std::string> ownerOf(const std::string &secret) {
        if (secret.rfind(kPrefix, 0) != 0) return std::nullopt;
        // Comparing digests, not secrets, so a timing difference reveals
        // nothing about any token.
        const std::string hash = sha256(secret);
        std::lock_guard<std::mutex> lock(g_mutex);
        loadLocked();
        for (const auto &s : g_tokens) {
            if (s.hash == hash) return s.info.user;
        }
        return std::nullopt;
    }

} // namespace tokens
} // namespace auth
} // namespace provisioner
