#pragma once

#include "utils.h"

#include <json/json.h>
#include <optional>
#include <string>
#include <vector>

namespace provisioner {
namespace keyregistry {

    constexpr const char* REGISTRY_PATH = "/etc/rpi-sb-provisioner/keys/registry.json";

    struct RegistryKey {
        std::string id;
        std::string type;           // "pem" | "pkcs11"
        std::string label;
        std::string path;           // PEM only
        std::string uri;            // PKCS#11 only
        std::string fingerprint;
        std::string algorithm;
        int keySize = 0;
        bool isFitForPurpose = false;
        std::string statusMessage;
        std::string statusLevel;
        bool wrapped = false;       // PEM at-rest wrap; always true for pkcs11 (not on disk)
        std::string addedAt;
    };

    struct RegistrySnapshot {
        std::string activeKeyId;
        std::vector<RegistryKey> keys;
    };

    bool load(RegistrySnapshot& out);
    bool save(const RegistrySnapshot& snapshot);

    // Import legacy single-key config entries into the registry when empty.
    void ensureMigratedFromConfig();

    std::string generateKeyId();

    std::optional<RegistryKey> findById(const RegistrySnapshot& snapshot, const std::string& id);
    std::optional<RegistryKey> findActive(const RegistrySnapshot& snapshot);

    // Add a key to the registry. Does not activate unless activate=true.
    std::optional<std::string> addPemKey(const std::string& path,
                                         const std::string& label,
                                         const utils::KeyInfo& info,
                                         bool wrapped,
                                         bool activate);

    std::optional<std::string> addPkcs11Key(const std::string& uri,
                                            const std::string& label,
                                            const utils::KeyInfo& info,
                                            bool activate);

    bool removeKey(const std::string& id, std::string& errorOut);

    // Set active key and sync CUSTOMER_KEY_* config vars. Returns true if the
    // secure-boot fingerprint changed (workdir cache should be invalidated).
    bool activateKey(const std::string& id, std::string& errorOut);

    void keyToJson(const RegistryKey& key, Json::Value& out);
    Json::Value snapshotToJson(const RegistrySnapshot& snapshot);

    bool refreshKeyMetadata(const std::string& id, std::string& errorOut);

} // namespace keyregistry
} // namespace provisioner
