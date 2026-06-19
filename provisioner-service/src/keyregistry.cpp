#include "keyregistry.h"

#include "keywrap.h"

#include <algorithm>
#include <chrono>
#include <cstdio>
#include <filesystem>
#include <fstream>
#include <iomanip>
#include <random>
#include <sstream>

#include <drogon/drogon.h>
#include "include/audit.h"

namespace provisioner {
namespace keyregistry {

namespace {

    std::string isoTimestampNow() {
        const auto now = std::chrono::system_clock::now();
        const std::time_t t = std::chrono::system_clock::to_time_t(now);
        std::tm tm{};
        gmtime_r(&t, &tm);
        char buf[32];
        std::strftime(buf, sizeof(buf), "%Y-%m-%dT%H:%M:%SZ", &tm);
        return buf;
    }

    bool readRegistryFile(Json::Value& root) {
        std::ifstream in(REGISTRY_PATH);
        if (!in.is_open()) {
            root = Json::Value(Json::objectValue);
            root["activeKeyId"] = "";
            root["keys"] = Json::Value(Json::arrayValue);
            return true;
        }
        Json::CharReaderBuilder builder;
        std::string errs;
        if (!Json::parseFromStream(builder, in, &root, &errs)) {
            LOG_ERROR << "Failed to parse key registry: " << errs;
            return false;
        }
        if (!root.isMember("keys") || !root["keys"].isArray()) {
            root["keys"] = Json::Value(Json::arrayValue);
        }
        if (!root.isMember("activeKeyId")) {
            root["activeKeyId"] = "";
        }
        return true;
    }

    bool writeRegistryFile(const Json::Value& root) {
        try {
            const auto dir = std::filesystem::path(REGISTRY_PATH).parent_path();
            if (!std::filesystem::exists(dir)) {
                std::filesystem::create_directories(dir);
                std::filesystem::permissions(dir,
                    std::filesystem::perms::owner_all,
                    std::filesystem::perm_options::replace);
            }
        } catch (const std::filesystem::filesystem_error& e) {
            LOG_ERROR << "Failed to create key registry directory: " << e.what();
            return false;
        }

        std::ofstream out(REGISTRY_PATH, std::ios::trunc);
        if (!out.is_open()) {
            LOG_ERROR << "Failed to open key registry for writing";
            return false;
        }
        out << root.toStyledString();
        out.close();
        try {
            std::filesystem::permissions(REGISTRY_PATH,
                std::filesystem::perms::owner_read | std::filesystem::perms::owner_write,
                std::filesystem::perm_options::replace);
        } catch (const std::filesystem::filesystem_error& e) {
            LOG_WARN << "Failed to set registry permissions: " << e.what();
        }
        return true;
    }

    RegistryKey parseKeyJson(const Json::Value& k) {
        RegistryKey key;
        key.id = k.get("id", "").asString();
        key.type = k.get("type", "").asString();
        key.label = k.get("label", "").asString();
        key.path = k.get("path", "").asString();
        key.uri = k.get("uri", "").asString();
        key.fingerprint = k.get("fingerprint", "").asString();
        key.algorithm = k.get("algorithm", "").asString();
        key.keySize = k.get("keySize", 0).asInt();
        key.isFitForPurpose = k.get("isFitForPurpose", false).asBool();
        key.statusMessage = k.get("statusMessage", "").asString();
        key.statusLevel = k.get("statusLevel", "").asString();
        key.wrapped = k.get("wrapped", false).asBool();
        key.addedAt = k.get("addedAt", "").asString();
        return key;
    }

    void populateKeyJson(const RegistryKey& key, Json::Value& k) {
        k["id"] = key.id;
        k["type"] = key.type;
        k["label"] = key.label;
        if (!key.path.empty()) k["path"] = key.path;
        if (!key.uri.empty()) k["uri"] = key.uri;
        k["fingerprint"] = key.fingerprint;
        k["algorithm"] = key.algorithm;
        k["keySize"] = key.keySize;
        k["isFitForPurpose"] = key.isFitForPurpose;
        k["statusMessage"] = key.statusMessage;
        k["statusLevel"] = key.statusLevel;
        k["wrapped"] = key.wrapped;
        k["addedAt"] = key.addedAt;
    }

    RegistryKey keyInfoToRegistryKey(const std::string& id,
                                     const std::string& type,
                                     const std::string& label,
                                     const std::string& path,
                                     const std::string& uri,
                                     bool wrapped,
                                     const utils::KeyInfo& info) {
        RegistryKey key;
        key.id = id;
        key.type = type;
        key.label = label;
        key.path = path;
        key.uri = uri;
        key.fingerprint = info.fingerprint;
        key.algorithm = info.algorithm;
        key.keySize = info.keySize;
        key.isFitForPurpose = info.isFitForPurpose;
        key.statusMessage = info.statusMessage;
        key.statusLevel = info.statusLevel;
        key.wrapped = wrapped;
        key.addedAt = isoTimestampNow();
        return key;
    }

    bool writeConfigFromActive(const RegistryKey* active) {
        auto existing = utils::getAllConfigValues();
        existing["CUSTOMER_KEY_FILE_PEM"] = "";
        existing["CUSTOMER_KEY_PKCS11_NAME"] = "";

        if (active) {
            if (active->type == "pem") {
                existing["CUSTOMER_KEY_FILE_PEM"] = active->path;
            } else if (active->type == "pkcs11") {
                existing["CUSTOMER_KEY_PKCS11_NAME"] = active->uri;
            }
        }

        std::ofstream configWrite(utils::CONFIG_USER_PATH);
        if (!configWrite.is_open()) {
            LOG_ERROR << "Failed to open config for key activation";
            return false;
        }
        for (const auto& [k, v] : existing) {
            configWrite << k << "=" << v << "\n";
        }
        configWrite.close();
        return true;
    }

    std::optional<std::string> previousActiveFingerprint() {
        RegistrySnapshot snap;
        if (!load(snap)) return std::nullopt;
        if (auto active = findActive(snap)) {
            return active->fingerprint;
        }
        return std::nullopt;
    }

} // namespace

std::string generateKeyId() {
    static std::random_device rd;
    static std::mt19937 gen(rd());
    static std::uniform_int_distribution<int> dist(0, 15);
    std::string id;
    id.reserve(32);
    for (int i = 0; i < 32; ++i) {
        id.push_back("0123456789abcdef"[dist(gen)]);
    }
    return id;
}

bool load(RegistrySnapshot& out) {
    Json::Value root;
    if (!readRegistryFile(root)) {
        return false;
    }
    out.activeKeyId = root["activeKeyId"].asString();
    out.keys.clear();
    for (const auto& k : root["keys"]) {
        out.keys.push_back(parseKeyJson(k));
    }
    return true;
}

bool save(const RegistrySnapshot& snapshot) {
    Json::Value root(Json::objectValue);
    root["activeKeyId"] = snapshot.activeKeyId;
    root["keys"] = Json::Value(Json::arrayValue);
    for (const auto& key : snapshot.keys) {
        Json::Value k;
        populateKeyJson(key, k);
        root["keys"].append(k);
    }
    return writeRegistryFile(root);
}

void ensureMigratedFromConfig() {
    RegistrySnapshot snap;
    if (!load(snap)) return;
    if (!snap.keys.empty()) return;

    auto pemPath = utils::getConfigValue("CUSTOMER_KEY_FILE_PEM");
    auto pkcs11Uri = utils::getConfigValue("CUSTOMER_KEY_PKCS11_NAME");

    if (pemPath && !pemPath->empty() && std::filesystem::exists(*pemPath)) {
        auto info = utils::parseKeyFile(*pemPath);
        if (info.success) {
            std::ifstream kin(*pemPath, std::ios::binary);
            const std::string raw((std::istreambuf_iterator<char>(kin)),
                                  std::istreambuf_iterator<char>());
            const bool wrapped = keywrap::isWrapped(raw);
            const std::string id = generateKeyId();
            std::filesystem::path p(*pemPath);
            snap.keys.push_back(keyInfoToRegistryKey(
                id, "pem", p.filename().string(), *pemPath, "", wrapped, info));
            snap.activeKeyId = id;
            save(snap);
            LOG_INFO << "Migrated legacy PEM key into registry: " << *pemPath;
            return;
        }
    }

    if (pkcs11Uri && !pkcs11Uri->empty()) {
        auto info = utils::parsePkcs11Key(*pkcs11Uri);
        if (info.success) {
            const std::string id = generateKeyId();
            std::string label = *pkcs11Uri;
            const auto objPos = pkcs11Uri->find("object=");
            if (objPos != std::string::npos) {
                auto end = pkcs11Uri->find(';', objPos);
                label = pkcs11Uri->substr(objPos + 7,
                    end == std::string::npos ? std::string::npos : end - objPos - 7);
            }
            snap.keys.push_back(keyInfoToRegistryKey(
                id, "pkcs11", label, "", *pkcs11Uri, true, info));
            snap.activeKeyId = id;
            save(snap);
            LOG_INFO << "Migrated legacy PKCS#11 key into registry";
        }
    }
}

std::optional<RegistryKey> findById(const RegistrySnapshot& snapshot, const std::string& id) {
    for (const auto& key : snapshot.keys) {
        if (key.id == id) return key;
    }
    return std::nullopt;
}

std::optional<RegistryKey> findActive(const RegistrySnapshot& snapshot) {
    if (snapshot.activeKeyId.empty()) return std::nullopt;
    return findById(snapshot, snapshot.activeKeyId);
}

std::optional<std::string> addPemKey(const std::string& path,
                                     const std::string& label,
                                     const utils::KeyInfo& info,
                                     bool wrapped,
                                     bool activate) {
    RegistrySnapshot snap;
    if (!load(snap)) return std::nullopt;

    for (const auto& existing : snap.keys) {
        if (existing.type == "pem" && existing.path == path) {
            if (activate) {
                std::string err;
                activateKey(existing.id, err);
            }
            return existing.id;
        }
    }

    const std::string id = generateKeyId();
    snap.keys.push_back(keyInfoToRegistryKey(id, "pem", label, path, "", wrapped, info));
    if (activate || snap.activeKeyId.empty()) {
        snap.activeKeyId = id;
        if (!writeConfigFromActive(&snap.keys.back())) {
            return std::nullopt;
        }
    }
    if (!save(snap)) return std::nullopt;
    AuditLog::logFileSystemAccess("REGISTER_KEY", path, true, "", id);
    return id;
}

std::optional<std::string> addPkcs11Key(const std::string& uri,
                                        const std::string& label,
                                        const utils::KeyInfo& info,
                                        bool activate) {
    RegistrySnapshot snap;
    if (!load(snap)) return std::nullopt;

    for (const auto& existing : snap.keys) {
        if (existing.type == "pkcs11" && existing.uri == uri) {
            if (activate) {
                std::string err;
                activateKey(existing.id, err);
            }
            return existing.id;
        }
    }

    const std::string id = generateKeyId();
    snap.keys.push_back(keyInfoToRegistryKey(id, "pkcs11", label, "", uri, true, info));
    if (activate || snap.activeKeyId.empty()) {
        snap.activeKeyId = id;
        if (!writeConfigFromActive(&snap.keys.back())) {
            return std::nullopt;
        }
    }
    if (!save(snap)) return std::nullopt;
    AuditLog::logFileSystemAccess("REGISTER_KEY", uri, true, "", id);
    return id;
}

bool removeKey(const std::string& id, std::string& errorOut) {
    RegistrySnapshot snap;
    if (!load(snap)) {
        errorOut = "Failed to load key registry";
        return false;
    }

    auto it = std::find_if(snap.keys.begin(), snap.keys.end(),
                           [&](const RegistryKey& k) { return k.id == id; });
    if (it == snap.keys.end()) {
        errorOut = "Key not found";
        return false;
    }

    if (snap.activeKeyId == id) {
        errorOut = "Cannot remove the active signing key. Activate a different key first.";
        return false;
    }

    if (it->type == "pem" && !it->path.empty()) {
        try {
            if (std::filesystem::exists(it->path)) {
                std::filesystem::remove(it->path);
                AuditLog::logFileSystemAccess("DELETE_KEY", it->path, true, "", id);
            }
        } catch (const std::filesystem::filesystem_error& e) {
            LOG_WARN << "Failed to delete PEM file " << it->path << ": " << e.what();
        }
    }

    snap.keys.erase(it);
    if (!save(snap)) {
        errorOut = "Failed to save key registry";
        return false;
    }
    return true;
}

bool activateKey(const std::string& id, std::string& errorOut) {
    RegistrySnapshot snap;
    if (!load(snap)) {
        errorOut = "Failed to load key registry";
        return false;
    }

    auto keyOpt = findById(snap, id);
    if (!keyOpt) {
        errorOut = "Key not found";
        return false;
    }

    if (!keyOpt->isFitForPurpose) {
        errorOut = keyOpt->statusMessage.empty()
            ? "Key is not valid for Pi secure boot"
            : keyOpt->statusMessage;
        return false;
    }

    const auto prevFp = previousActiveFingerprint();
    snap.activeKeyId = id;
    if (!writeConfigFromActive(&*keyOpt)) {
        errorOut = "Failed to update configuration";
        return false;
    }
    if (!save(snap)) {
        errorOut = "Failed to save key registry";
        return false;
    }

    AuditLog::logFileSystemAccess("ACTIVATE_KEY",
                                  keyOpt->type == "pem" ? keyOpt->path : keyOpt->uri,
                                  true, "", id);

    return prevFp && *prevFp != keyOpt->fingerprint;
}

void keyToJson(const RegistryKey& key, Json::Value& out) {
    populateKeyJson(key, out);
}

Json::Value snapshotToJson(const RegistrySnapshot& snapshot) {
    Json::Value root;
    root["activeKeyId"] = snapshot.activeKeyId;
    root["keys"] = Json::Value(Json::arrayValue);
    for (const auto& key : snapshot.keys) {
        Json::Value k;
        keyToJson(key, k);
        root["keys"].append(k);
    }
    return root;
}

bool refreshKeyMetadata(const std::string& id, std::string& errorOut) {
    RegistrySnapshot snap;
    if (!load(snap)) {
        errorOut = "Failed to load key registry";
        return false;
    }

    for (auto& key : snap.keys) {
        if (key.id != id) continue;

        utils::KeyInfo info;
        if (key.type == "pem") {
            if (key.path.empty() || !std::filesystem::exists(key.path)) {
                errorOut = "PEM key file not found";
                return false;
            }
            info = utils::parseKeyFile(key.path);
            std::ifstream in(key.path, std::ios::binary);
            const std::string raw((std::istreambuf_iterator<char>(in)),
                                  std::istreambuf_iterator<char>());
            key.wrapped = keywrap::isWrapped(raw);
        } else if (key.type == "pkcs11") {
            info = utils::parsePkcs11Key(key.uri);
        } else {
            errorOut = "Unknown key type";
            return false;
        }

        if (!info.success) {
            errorOut = info.errorMessage.empty() ? "Key validation failed" : info.errorMessage;
            return false;
        }

        key.fingerprint = info.fingerprint;
        key.algorithm = info.algorithm;
        key.keySize = info.keySize;
        key.isFitForPurpose = info.isFitForPurpose;
        key.statusMessage = info.statusMessage;
        key.statusLevel = info.statusLevel;
        if (!save(snap)) {
            errorOut = "Failed to save key registry";
            return false;
        }
        return true;
    }

    errorOut = "Key not found";
    return false;
}

} // namespace keyregistry
} // namespace provisioner
