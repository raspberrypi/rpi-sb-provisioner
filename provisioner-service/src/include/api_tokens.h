#pragma once

#include <optional>
#include <string>
#include <vector>

namespace provisioner {
namespace auth {
namespace tokens {

    // Bearer tokens for scripted clients. Only a SHA-256 of each token is
    // kept, in a root-only file, so reading the file does not yield a token.
    inline constexpr const char *kStorePath = "/etc/rpi-sb-provisioner/api-tokens.json";

    struct TokenInfo {
        std::string id;
        std::string user;
        std::string label;
        std::string created;
    };

    // The secret is returned once and never stored.
    struct Created {
        TokenInfo info;
        std::string secret;
    };

    std::optional<Created> create(const std::string &user, const std::string &label, std::string &error);
    bool revoke(const std::string &id, std::string &revokedOwner);
    std::vector<TokenInfo> list();

    // The owning user for a presented secret, or nullopt.
    std::optional<std::string> ownerOf(const std::string &secret);

} // namespace tokens
} // namespace auth
} // namespace provisioner
