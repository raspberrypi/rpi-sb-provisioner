#pragma once

// The OS images under IMAGES_PATH: whether one is whole, and how one is
// replaced so that a crash, a restart or a power cut at any point leaves the
// old image or the new one in place, never a mix. Anything built from an
// image records the image's identity and is rebuilt when it stops matching.
//
// Drogon-free, so osimage_test runs it without a station.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <sys/types.h>
#include <vector>

namespace provisioner::osimage {

    // Device, inode, size and modification time, exactly as
    // stat -c '%d:%i:%s:%.9Y' prints them, so the provisioning scripts can
    // compare it too. A replaced image always has a new inode. "" if absent.
    std::string identity(const std::filesystem::path& p);

    // Flushes a file, or a directory's entries, to the disk.
    bool sync(const std::filesystem::path& p);

    // Writes data beside path, syncs it, renames it over path and syncs the
    // directory: readers and a power cut see the old contents or the new.
    // Returns why it failed, or "".
    std::string writeDurably(const std::filesystem::path& path, std::string_view data,
                             mode_t mode = 0640);

    // How long an image's partition table says the image must be: the end of
    // its last partition. nullopt when there is no table to go by, as for a
    // bare filesystem.
    struct Extent {
        std::string scheme;     // "MBR" or "GPT"
        std::uint64_t needed;   // bytes
    };
    std::optional<Extent> declaredExtent(const std::filesystem::path& p);

    // "" when the image holds every partition its table declares; otherwise
    // what to tell the operator.
    std::string checkWhole(const std::filesystem::path& p);

    // "1.23 GB": decimal units, as the operator's file manager shows them.
    std::string formatSize(std::uint64_t bytes);

    // The .sha256 sidecar holds "<sha256> <identity>". The hash is returned
    // only while the identity still matches the image, so a replaced image
    // never inherits one. An IDP artefact's sidecar from before identities is
    // still believed: it holds the archive's hash, which cannot be redone.
    std::filesystem::path sidecarPath(const std::filesystem::path& image);
    std::string readSidecarHash(const std::filesystem::path& image);
    std::string writeSidecar(const std::filesystem::path& image, const std::string& sha256,
                             const std::string& imageIdentity);

    // Where an upload is written before it is complete.
    std::filesystem::path stagingPath(const std::filesystem::path& dir, const std::string& name);

    // Removes what an interrupted upload, extraction or durable write left
    // in dir. Only names starting with a dot are ours: image names cannot.
    // Call before anything else touches dir. Returns the names removed.
    std::vector<std::string> sweep(const std::filesystem::path& dir);

    // Puts a complete, staged image at target. A file replaces a file with
    // one rename; a directory is exchanged with the old one, which is then
    // deleted. Syncs the staged data first and the directory after. Returns
    // why it failed, or "", and says whether something was replaced.
    std::string install(const std::filesystem::path& staged, const std::filesystem::path& target,
                        bool& replaced);

    // Provisioning runs hold this shared for as long as they use an image
    // (hold_gold_master_os in rpi-sb-common.sh). Replacing or deleting the
    // image takes it exclusively, without waiting. The kernel drops a dead
    // process's lock, so a crash never leaves an image marked in use.
    constexpr const char* LOCK_DIR = "/srv/rpi-sb-provisioner/locks/os-image";

    class ImageLock {
    public:
        // nullopt with why set when the image is in use or the lock cannot
        // be made.
        static std::optional<ImageLock> tryExclusive(const std::filesystem::path& lockDir,
                                                     const std::string& name, std::string& why);
        ImageLock(ImageLock&& o) noexcept : fd_(o.fd_) { o.fd_ = -1; }
        ImageLock& operator=(ImageLock&&) = delete;
        ImageLock(const ImageLock&) = delete;
        ~ImageLock();
    private:
        explicit ImageLock(int fd) : fd_(fd) {}
        int fd_;
    };

} // namespace provisioner::osimage
