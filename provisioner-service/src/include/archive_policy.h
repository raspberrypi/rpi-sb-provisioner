#pragma once

#include <archive.h>
#include <archive_entry.h>

#include <string>

namespace provisioner {
namespace archive_policy {

    // Extraction runs as root, and the archive comes from whoever built the
    // image. These refuse to follow a symlink part-way through a path or to
    // climb out with "..", on top of the entry checks below.
    inline constexpr int kExtractFlags = ARCHIVE_EXTRACT_TIME | ARCHIVE_EXTRACT_PERM |
                                         ARCHIVE_EXTRACT_NO_OVERWRITE |
                                         ARCHIVE_EXTRACT_SECURE_SYMLINKS |
                                         ARCHIVE_EXTRACT_SECURE_NODOTDOT;

    // Relative, and never "..", so it can only name something below its root.
    inline bool isContainedPath(const std::string &path) {
        return !path.empty() && path[0] != '/' && path.find("..") == std::string::npos;
    }

    // Admits only what an image archive needs: files, directories, symlinks
    // that point further into the archive, and hardlinks to its own entries.
    // Rewrites the entry, and any hardlink, under root, which must be a
    // canonical path: SECURE_SYMLINKS rejects a symlink anywhere in it.
    inline bool admit(struct archive_entry *entry, const std::string &root, std::string &error) {
        const char *rawPath = archive_entry_pathname(entry);
        const std::string path = rawPath ? rawPath : "";
        if (!isContainedPath(path)) {
            error = "unsafe path: " + path;
            return false;
        }

        // A hardlink entry carries no file type of its own, only the name of
        // the earlier entry it shares.
        if (const char *link = archive_entry_hardlink(entry)) {
            if (!isContainedPath(link)) {
                error = "hardlink leaves the archive: " + path;
                return false;
            }
            archive_entry_set_hardlink(entry, (root + "/" + link).c_str());
        } else {
            switch (archive_entry_filetype(entry)) {
                case AE_IFREG:
                case AE_IFDIR:
                    break;
                case AE_IFLNK: {
                    const char *target = archive_entry_symlink(entry);
                    if (!target || !isContainedPath(target)) {
                        error = "symlink leaves the archive: " + path;
                        return false;
                    }
                    break;
                }
                default:
                    error = "unsupported entry type: " + path;
                    return false;
            }
        }
        archive_entry_set_pathname(entry, (root + "/" + path).c_str());
        return true;
    }

} // namespace archive_policy
} // namespace provisioner
