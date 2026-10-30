#include "osimage.h"

#include <algorithm>
#include <array>
#include <cerrno>
#include <cinttypes>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <sys/file.h>
#include <sys/stat.h>
#include <unistd.h>

namespace provisioner::osimage {

    namespace {
        std::string errnoText(const char* step) {
            return std::string(step) + ": " + std::strerror(errno);
        }

        std::uint32_t le32(const unsigned char* p) {
            return std::uint32_t(p[0]) | std::uint32_t(p[1]) << 8 |
                   std::uint32_t(p[2]) << 16 | std::uint32_t(p[3]) << 24;
        }

        std::uint64_t le64(const unsigned char* p) {
            return std::uint64_t(le32(p)) | std::uint64_t(le32(p + 4)) << 32;
        }

        bool readAt(int fd, void* buf, size_t len, off_t at) {
            auto* out = static_cast<unsigned char*>(buf);
            while (len > 0) {
                const ssize_t n = pread(fd, out, len, at);
                if (n < 0 && errno == EINTR) continue;
                if (n <= 0) return false;
                out += n;
                len -= size_t(n);
                at += n;
            }
            return true;
        }

        // The GPT header and entries, for a given logical block size. The
        // primary header sits in the first block, so a short image still has
        // it to read.
        std::optional<Extent> gptExtent(int fd, std::uint64_t lba) {
            unsigned char hdr[92];
            if (!readAt(fd, hdr, sizeof hdr, off_t(lba)) || std::memcmp(hdr, "EFI PART", 8) != 0)
                return std::nullopt;
            const std::uint64_t entriesLba = le64(hdr + 72);
            const std::uint32_t count = le32(hdr + 80);
            const std::uint32_t size = le32(hdr + 84);
            if (count == 0 || count > 1024 || size < 128 || size > 4096) return std::nullopt;

            std::vector<unsigned char> entries(size_t(count) * size);
            if (!readAt(fd, entries.data(), entries.size(), off_t(entriesLba * lba))) return std::nullopt;

            std::uint64_t end = 0;
            for (std::uint32_t i = 0; i < count; ++i) {
                const unsigned char* e = entries.data() + size_t(i) * size;
                if (std::all_of(e, e + 16, [](unsigned char b) { return b == 0; })) continue;
                end = std::max(end, (le64(e + 40) + 1) * lba);
            }
            if (end == 0) return std::nullopt;
            return Extent{"GPT", end};
        }

        // A FAT boot sector ends 55 AA like an MBR. Its jump instruction and
        // filesystem name tell the two apart.
        bool looksLikeFatBootSector(const unsigned char* s) {
            const bool jump = (s[0] == 0xEB && s[2] == 0x90) || s[0] == 0xE9;
            return jump && (std::memcmp(s + 0x36, "FAT", 3) == 0 || std::memcmp(s + 0x52, "FAT", 3) == 0);
        }
    }

    std::string identity(const std::filesystem::path& p) {
        struct stat st;
        if (stat(p.c_str(), &st) != 0) return "";
        char buf[128];
        std::snprintf(buf, sizeof buf, "%" PRIuMAX ":%" PRIuMAX ":%" PRIdMAX ":%" PRIdMAX ".%09ld",
                      uintmax_t(st.st_dev), uintmax_t(st.st_ino), intmax_t(st.st_size),
                      intmax_t(st.st_mtim.tv_sec), long(st.st_mtim.tv_nsec));
        return buf;
    }

    bool sync(const std::filesystem::path& p) {
        const int fd = open(p.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return false;
        const bool ok = fsync(fd) == 0;
        close(fd);
        return ok;
    }

    std::string writeDurably(const std::filesystem::path& path, std::string_view data, mode_t mode) {
        std::filesystem::path tmp = path.parent_path() / ("." + path.filename().string() + ".XXXXXX.tmp");
        std::string name = tmp.string();
        const int fd = mkstemps(name.data(), 4);
        if (fd < 0) return errnoText("mkstemps");

        auto fail = [&](const char* step) {
            const std::string why = errnoText(step);
            close(fd);
            unlink(name.c_str());
            return why;
        };
        for (size_t done = 0; done < data.size();) {
            const ssize_t n = write(fd, data.data() + done, data.size() - done);
            if (n < 0) {
                if (errno == EINTR) continue;
                return fail("write");
            }
            done += size_t(n);
        }
        if (fchmod(fd, mode) != 0) return fail("fchmod");
        if (fsync(fd) != 0) return fail("fsync");
        close(fd);
        if (rename(name.c_str(), path.c_str()) != 0) {
            const std::string why = errnoText("rename");
            unlink(name.c_str());
            return why;
        }
        if (!sync(path.parent_path())) return errnoText("fsync directory");
        return "";
    }

    std::optional<Extent> declaredExtent(const std::filesystem::path& p) {
        const int fd = open(p.c_str(), O_RDONLY | O_CLOEXEC);
        if (fd < 0) return std::nullopt;
        std::optional<Extent> found;

        unsigned char mbr[512];
        if (readAt(fd, mbr, sizeof mbr, 0) && mbr[510] == 0x55 && mbr[511] == 0xAA &&
            !looksLikeFatBootSector(mbr)) {
            bool plausible = true, protective = false;
            std::uint64_t end = 0;
            for (int i = 0; i < 4; ++i) {
                const unsigned char* e = mbr + 446 + 16 * i;
                const std::uint32_t start = le32(e + 8), sectors = le32(e + 12);
                if (e[0] != 0x00 && e[0] != 0x80) plausible = false;
                if (e[4] == 0) continue;
                if (e[4] == 0xEE) protective = true;
                if (start == 0 || sectors == 0) plausible = false;
                // An extended partition's entry spans its logical ones.
                end = std::max(end, (std::uint64_t(start) + sectors) * 512);
            }
            if (plausible && protective) {
                found = gptExtent(fd, 512);
                if (!found) found = gptExtent(fd, 4096);
            } else if (plausible && end > 0) {
                found = Extent{"MBR", end};
            }
        }
        close(fd);
        return found;
    }

    std::string formatSize(std::uint64_t bytes) {
        char buf[32];
        if (bytes >= 1000000000ULL)
            std::snprintf(buf, sizeof buf, "%.2f GB", double(bytes) / 1e9);
        else if (bytes >= 1000000ULL)
            std::snprintf(buf, sizeof buf, "%.1f MB", double(bytes) / 1e6);
        else
            std::snprintf(buf, sizeof buf, "%" PRIu64 " bytes", bytes);
        return buf;
    }

    std::string checkWhole(const std::filesystem::path& p) {
        std::error_code ec;
        const std::uint64_t have = std::filesystem::file_size(p, ec);
        if (ec) return "Could not read the image's size: " + ec.message();
        const auto extent = declaredExtent(p);
        if (!extent || have >= extent->needed) return "";
        return "This image is cut short: it is " + formatSize(have) + ", but its " + extent->scheme +
               " partition table needs " + formatSize(extent->needed) + " (" +
               formatSize(extent->needed - have) + " missing). The file was incomplete before it was "
               "uploaded. Copy it to this station again, then upload it again.";
    }

    std::filesystem::path sidecarPath(const std::filesystem::path& image) {
        std::filesystem::path s = image;
        s += ".sha256";
        return s;
    }

    std::string readSidecarHash(const std::filesystem::path& image) {
        std::ifstream in(sidecarPath(image));
        std::string hash, id;
        if (!(in >> hash) || hash.size() != 64) return "";
        in >> id;
        std::error_code ec;
        if (id.empty()) return std::filesystem::is_directory(image, ec) ? hash : "";
        return id == identity(image) ? hash : "";
    }

    std::string writeSidecar(const std::filesystem::path& image, const std::string& sha256,
                             const std::string& imageIdentity) {
        return writeDurably(sidecarPath(image), sha256 + " " + imageIdentity + "\n", 0640);
    }

    std::filesystem::path stagingPath(const std::filesystem::path& dir, const std::string& name) {
        return dir / ("." + name + ".uploading");
    }

    std::vector<std::string> sweep(const std::filesystem::path& dir) {
        static constexpr std::array<std::string_view, 5> ours = {
            ".uploading", ".extracting", ".promoted", ".old", ".tmp"};
        std::vector<std::string> removed;
        std::error_code ec;
        for (const auto& entry : std::filesystem::directory_iterator(dir, ec)) {
            const std::string name = entry.path().filename().string();
            if (name.size() < 2 || name[0] != '.') continue;
            const bool match = std::any_of(ours.begin(), ours.end(), [&](std::string_view s) {
                return name.size() > s.size() && name.compare(name.size() - s.size(), s.size(), s) == 0;
            });
            if (!match) continue;
            std::error_code rmec;
            std::filesystem::remove_all(entry.path(), rmec);
            if (!rmec) removed.push_back(name);
        }
        if (!removed.empty()) sync(dir);
        return removed;
    }

    std::string install(const std::filesystem::path& staged, const std::filesystem::path& target,
                        bool& replaced) {
        replaced = false;
        std::error_code ec;
        const bool stagedIsDir = std::filesystem::is_directory(staged, ec);
        const auto targetStatus = std::filesystem::symlink_status(target, ec);
        const bool exists = std::filesystem::exists(targetStatus);
        if (exists && std::filesystem::is_directory(targetStatus) != stagedIsDir)
            return stagedIsDir ? "a disk image of that name already exists"
                               : "an IDP artefact of that name already exists";

        // Every byte reaches the disk before the name points at it.
        if (stagedIsDir) {
            const int fd = open(staged.c_str(), O_RDONLY | O_DIRECTORY | O_CLOEXEC);
            if (fd < 0) return errnoText("open staged directory");
            const int rc = syncfs(fd);
            close(fd);
            if (rc != 0) return errnoText("syncfs");
        } else if (!sync(staged)) {
            return errnoText("fsync");
        }

        if (exists && stagedIsDir) {
            // The old directory ends up at the staged name, where it is
            // deleted now, or by sweep() after a crash.
            if (renameat2(AT_FDCWD, staged.c_str(), AT_FDCWD, target.c_str(), RENAME_EXCHANGE) != 0)
                return errnoText("exchange");
            replaced = true;
            sync(target.parent_path());
            std::filesystem::remove_all(staged, ec);
        } else {
            if (rename(staged.c_str(), target.c_str()) != 0) return errnoText("rename");
            replaced = exists;
        }
        if (!sync(target.parent_path())) return errnoText("fsync directory");
        return "";
    }

    std::optional<ImageLock> ImageLock::tryExclusive(const std::filesystem::path& lockDir,
                                                     const std::string& name, std::string& why) {
        std::error_code ec;
        std::filesystem::create_directories(lockDir, ec);
        const std::filesystem::path path = lockDir / (name + ".lock");
        const int fd = open(path.c_str(), O_RDWR | O_CREAT | O_CLOEXEC, 0640);
        if (fd < 0) {
            why = errnoText("open lock");
            return std::nullopt;
        }
        if (flock(fd, LOCK_EX | LOCK_NB) != 0) {
            why = errno == EWOULDBLOCK
                ? "A device is being provisioned from this image. Try again when provisioning finishes."
                : errnoText("flock");
            close(fd);
            return std::nullopt;
        }
        return ImageLock(fd);
    }

    ImageLock::~ImageLock() {
        if (fd_ >= 0) close(fd_);
    }

} // namespace provisioner::osimage
