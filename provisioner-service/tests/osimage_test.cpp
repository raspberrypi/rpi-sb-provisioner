// Tests for osimage: no station, no root. Each test works in its own
// temporary directory. Exits non-zero if any check fails.

#include "osimage.h"

#include <array>
#include <csignal>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iostream>
#include <sstream>
#include <sys/file.h>
#include <sys/stat.h>
#include <sys/wait.h>
#include <unistd.h>
#include <vector>

namespace fs = std::filesystem;
using namespace provisioner::osimage;

static int failures = 0;
static const char* current = "";

#define CHECK(cond) do { if (!(cond)) { ++failures; \
    std::cerr << current << ": " << __FILE__ << ":" << __LINE__ << ": " #cond "\n"; } } while (0)

static fs::path scratch() {
    char tmpl[] = "/tmp/osimage-test.XXXXXX";
    return fs::path(mkdtemp(tmpl));
}

static void put(const fs::path& p, const std::string& data) {
    std::ofstream(p, std::ios::binary | std::ios::trunc) << data;
}

static std::string get(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static std::string shell(const std::string& cmd) {
    std::string out;
    FILE* f = popen(cmd.c_str(), "r");
    char buf[256];
    while (f && fgets(buf, sizeof buf, f)) out += buf;
    if (f) pclose(f);
    while (!out.empty() && out.back() == '\n') out.pop_back();
    return out;
}

static void le32(std::vector<unsigned char>& b, size_t at, uint32_t v) {
    for (int i = 0; i < 4; ++i) b[at + i] = (v >> (8 * i)) & 0xFF;
}

static void le64(std::vector<unsigned char>& b, size_t at, uint64_t v) {
    le32(b, at, uint32_t(v));
    le32(b, at + 4, uint32_t(v >> 32));
}

static void writeSized(const fs::path& p, const std::vector<unsigned char>& head, uint64_t size) {
    put(p, std::string(head.begin(), head.end()));
    fs::resize_file(p, size);
}

// A Raspberry Pi OS shaped image: a FAT partition then a Linux one.
static std::vector<unsigned char> mbrImage(uint64_t& needed) {
    std::vector<unsigned char> b(512, 0);
    const uint32_t parts[2][3] = {{0x0C, 8192, 1000}, {0x83, 9192, 2000}};
    for (int i = 0; i < 2; ++i) {
        b[446 + 16 * i + 4] = uint8_t(parts[i][0]);
        le32(b, 446 + 16 * i + 8, parts[i][1]);
        le32(b, 446 + 16 * i + 12, parts[i][2]);
    }
    b[510] = 0x55; b[511] = 0xAA;
    needed = (9192ULL + 2000) * 512;
    return b;
}

static std::vector<unsigned char> gptImage(uint64_t& needed) {
    std::vector<unsigned char> b(512 * 34, 0);
    b[446 + 4] = 0xEE;
    le32(b, 446 + 8, 1);
    le32(b, 446 + 12, 0xFFFFFFFF);
    b[510] = 0x55; b[511] = 0xAA;
    std::memcpy(&b[512], "EFI PART", 8);
    le64(b, 512 + 72, 2);      // entries at LBA 2
    le32(b, 512 + 80, 128);    // 128 entries
    le32(b, 512 + 84, 128);    // of 128 bytes
    for (int i = 0; i < 2; ++i) {
        const size_t e = 1024 + 128 * i;
        b[e] = 0xAF;           // any non-zero type GUID
        le64(b, e + 32, i == 0 ? 2048 : 4096);
        le64(b, e + 40, i == 0 ? 4095 : 20479);
    }
    needed = 20480ULL * 512;
    return b;
}

static void identityMatchesStat() {
    current = "identityMatchesStat";
    const fs::path d = scratch();
    put(d / "a.img", "hello");
    fs::create_directory(d / "idp");
    for (const char* n : {"a.img", "idp"}) {
        const fs::path p = d / n;
        CHECK(identity(p) == shell("stat -c '%d:%i:%s:%.9Y' '" + p.string() + "'"));
    }
    CHECK(identity(d / "absent").empty());

    const std::string before = identity(d / "a.img");
    put(d / "b.img", "hello");
    fs::rename(d / "b.img", d / "a.img");
    CHECK(identity(d / "a.img") != before);
    fs::remove_all(d);
}

static void writesDurably() {
    current = "writesDurably";
    const fs::path d = scratch();
    CHECK(writeDurably(d / "f", "one\n", 0600).empty());
    CHECK(writeDurably(d / "f", "two\n", 0600).empty());
    CHECK(get(d / "f") == "two\n");
    CHECK((fs::status(d / "f").permissions() & fs::perms::all) ==
          (fs::perms::owner_read | fs::perms::owner_write));
    CHECK(std::distance(fs::directory_iterator(d), fs::directory_iterator()) == 1);
    CHECK(!writeDurably(d / "missing-dir" / "f", "x").empty());
    fs::remove_all(d);
}

static void findsCutShortImages() {
    current = "findsCutShortImages";
    const fs::path d = scratch();
    uint64_t needed = 0;

    const auto mbr = mbrImage(needed);
    writeSized(d / "whole.img", mbr, needed);
    CHECK(declaredExtent(d / "whole.img").has_value());
    CHECK(declaredExtent(d / "whole.img")->scheme == "MBR");
    CHECK(declaredExtent(d / "whole.img")->needed == needed);
    CHECK(checkWhole(d / "whole.img").empty());
    writeSized(d / "longer.img", mbr, needed + 4096);
    CHECK(checkWhole(d / "longer.img").empty());
    writeSized(d / "short.img", mbr, needed - 100 * 512);
    const std::string why = checkWhole(d / "short.img");
    CHECK(why.find("cut short") != std::string::npos);
    CHECK(why.find("51200 bytes missing") != std::string::npos);
    CHECK(why.find("MBR") != std::string::npos);

    const auto gpt = gptImage(needed);
    writeSized(d / "gpt.img", gpt, needed);
    CHECK(declaredExtent(d / "gpt.img").has_value());
    CHECK(declaredExtent(d / "gpt.img")->scheme == "GPT");
    CHECK(checkWhole(d / "gpt.img").empty());
    writeSized(d / "gpt-short.img", gpt, needed - 512);
    CHECK(!checkWhole(d / "gpt-short.img").empty());

    // Nothing to go by: accepted rather than guessed at.
    writeSized(d / "blank.img", std::vector<unsigned char>(512, 0), 4096);
    CHECK(!declaredExtent(d / "blank.img").has_value());
    CHECK(checkWhole(d / "blank.img").empty());
    put(d / "tiny.img", "x");
    CHECK(checkWhole(d / "tiny.img").empty());

    // A bare FAT filesystem ends its boot sector 55 AA too, with boot code
    // where an MBR's entries would be.
    std::vector<unsigned char> fat(512, 0x41);
    fat[0] = 0xEB; fat[1] = 0x58; fat[2] = 0x90;
    std::memcpy(&fat[0x52], "FAT32   ", 8);
    fat[510] = 0x55; fat[511] = 0xAA;
    writeSized(d / "fat.img", fat, 4096);
    CHECK(!declaredExtent(d / "fat.img").has_value());

    // Garbage after 55 AA that cannot be a partition table.
    std::vector<unsigned char> junk(512, 0x41);
    junk[510] = 0x55; junk[511] = 0xAA;
    writeSized(d / "junk.img", junk, 4096);
    CHECK(!declaredExtent(d / "junk.img").has_value());
    fs::remove_all(d);
}

static void sidecarsFollowTheImage() {
    current = "sidecarsFollowTheImage";
    const fs::path d = scratch();
    const std::string hash(64, 'a');
    put(d / "a.img", "one");
    CHECK(writeSidecar(d / "a.img", hash, identity(d / "a.img")).empty());
    CHECK(readSidecarHash(d / "a.img") == hash);
    CHECK(shell("head -n1 '" + sidecarPath(d / "a.img").string() + "' | awk '{print $1}'") == hash);

    // Replaced: the old hash no longer speaks for the file at this name.
    put(d / "new.img", "two");
    fs::rename(d / "new.img", d / "a.img");
    CHECK(readSidecarHash(d / "a.img").empty());

    // Written by an earlier release: a hash alone proves nothing.
    put(sidecarPath(d / "a.img"), hash + "\n");
    CHECK(readSidecarHash(d / "a.img").empty());
    put(sidecarPath(d / "a.img"), "");
    CHECK(readSidecarHash(d / "a.img").empty());

    // An IDP artefact's archive hash cannot be recomputed, so an old one stands.
    fs::create_directory(d / "idp");
    put(sidecarPath(d / "idp"), hash + "\n");
    CHECK(readSidecarHash(d / "idp") == hash);
    put(sidecarPath(d / "idp"), hash + " 1:2:3:4.000000000\n");
    CHECK(readSidecarHash(d / "idp").empty());
    CHECK(writeSidecar(d / "idp", hash, identity(d / "idp")).empty());
    CHECK(readSidecarHash(d / "idp") == hash);
    fs::remove_all(d);
}

static void sweepsOnlyOurLeftovers() {
    current = "sweepsOnlyOurLeftovers";
    const fs::path d = scratch();
    put(stagingPath(d, "a.img"), "partial");
    fs::create_directory(d / ".b.extracting");
    put(d / ".b.extracting" / "x", "x");
    fs::create_directory(d / ".c.promoted");
    fs::create_directory(d / ".d.old");
    put(d / ".a.img.sha256.Ab12Cd.tmp", "x");
    put(d / "keep.img", "x");
    put(d / "keep.img.sha256", "x");
    put(d / ".keep", "x");
    fs::create_directory(d / "idp");

    const auto removed = sweep(d);
    CHECK(removed.size() == 5);
    for (const char* n : {"keep.img", "keep.img.sha256", ".keep", "idp"}) CHECK(fs::exists(d / n));
    CHECK(!fs::exists(stagingPath(d, "a.img")));
    CHECK(!fs::exists(d / ".b.extracting"));
    CHECK(sweep(d).empty());
    fs::remove_all(d);
}

static void installsAndReplaces() {
    current = "installsAndReplaces";
    const fs::path d = scratch();
    bool replaced = true;

    put(stagingPath(d, "a.img"), "one");
    CHECK(install(stagingPath(d, "a.img"), d / "a.img", replaced).empty());
    CHECK(!replaced);
    CHECK(get(d / "a.img") == "one");

    put(stagingPath(d, "a.img"), "two");
    CHECK(install(stagingPath(d, "a.img"), d / "a.img", replaced).empty());
    CHECK(replaced);
    CHECK(get(d / "a.img") == "two");
    CHECK(!fs::exists(stagingPath(d, "a.img")));

    fs::create_directory(d / ".idp.extracting");
    put(d / ".idp.extracting" / "v", "one");
    CHECK(install(d / ".idp.extracting", d / "idp", replaced).empty());
    CHECK(!replaced);
    fs::create_directory(d / ".idp.extracting");
    put(d / ".idp.extracting" / "v", "two");
    CHECK(install(d / ".idp.extracting", d / "idp", replaced).empty());
    CHECK(replaced);
    CHECK(get(d / "idp" / "v") == "two");
    CHECK(!fs::exists(d / ".idp.extracting"));

    // A file cannot replace a directory, nor the other way round.
    put(stagingPath(d, "idp"), "file");
    CHECK(!install(stagingPath(d, "idp"), d / "idp", replaced).empty());
    CHECK(get(d / "idp" / "v") == "two");
    fs::remove_all(d);
}

// A provisioning run, as rpi-sb-common.sh holds the lock: shared, in another
// process.
static pid_t holdShared(const fs::path& lockFile) {
    int ready[2];
    if (pipe(ready) != 0) return -1;
    const pid_t pid = fork();
    if (pid == 0) {
        const int fd = open(lockFile.c_str(), O_RDWR | O_CREAT, 0640);
        flock(fd, LOCK_SH);
        (void)!write(ready[1], "x", 1);
        pause();
        _exit(0);
    }
    char c;
    (void)!read(ready[0], &c, 1);
    close(ready[0]);
    close(ready[1]);
    return pid;
}

static void locksOutReplacementWhileInUse() {
    current = "locksOutReplacementWhileInUse";
    const fs::path d = scratch();
    std::string why;
    {
        auto lock = ImageLock::tryExclusive(d / "locks", "a.img", why);
        CHECK(lock.has_value());
        std::string again;
        CHECK(!ImageLock::tryExclusive(d / "locks", "a.img", again).has_value());
        CHECK(ImageLock::tryExclusive(d / "locks", "b.img", again).has_value());
    }
    CHECK(ImageLock::tryExclusive(d / "locks", "a.img", why).has_value());

    const pid_t run = holdShared(d / "locks" / "a.img.lock");
    why.clear();
    CHECK(!ImageLock::tryExclusive(d / "locks", "a.img", why).has_value());
    CHECK(why.find("being provisioned") != std::string::npos);

    // The run dies without cleaning up: the kernel lets the lock go.
    kill(run, SIGKILL);
    waitpid(run, nullptr, 0);
    CHECK(ImageLock::tryExclusive(d / "locks", "a.img", why).has_value());
    fs::remove_all(d);
}

int main() {
    const std::array<std::function<void()>, 7> tests = {
        identityMatchesStat, writesDurably, findsCutShortImages, sidecarsFollowTheImage,
        sweepsOnlyOurLeftovers, installsAndReplaces, locksOutReplacementWhileInUse};
    for (const auto& t : tests) t();
    if (failures) std::cerr << failures << " check(s) failed\n";
    else std::cout << "osimage: all checks passed\n";
    return failures ? 1 : 0;
}
