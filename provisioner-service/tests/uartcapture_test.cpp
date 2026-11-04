// Tests for uartcapture and rpi-sb-uart-capture: no station, no root. The
// daemon runs against a pseudo-terminal standing in for the jig's UART.
// Usage: uartcapture_test <path to rpi-sb-uart-capture>

#include "uartcapture.h"

#include <chrono>
#include <csignal>
#include <cstdlib>
#include <fcntl.h>
#include <fstream>
#include <functional>
#include <iostream>
#include <pty.h>
#include <sstream>
#include <sys/wait.h>
#include <thread>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace provisioner::uartcapture;

static int failures = 0;
static const char* current = "";

#define CHECK(cond) do { if (!(cond)) { ++failures; \
    std::cerr << current << ": " << __FILE__ << ":" << __LINE__ << ": " #cond "\n"; } } while (0)

static fs::path scratch() {
    char tmpl[] = "/tmp/uartcapture-test.XXXXXX";
    return fs::path(mkdtemp(tmpl));
}

static void put(const fs::path& p, const std::string& data) {
    fs::create_directories(p.parent_path());
    std::ofstream(p, std::ios::binary | std::ios::trunc) << data;
}

static std::string get(const fs::path& p) {
    std::ifstream in(p, std::ios::binary);
    std::stringstream ss;
    ss << in.rdbuf();
    return ss.str();
}

static int count(const std::string& hay, const std::string& needle) {
    int n = 0;
    for (auto at = hay.find(needle); at != std::string::npos; at = hay.find(needle, at + 1)) ++n;
    return n;
}

// Waits up to 5 s for test() to hold.
static bool eventually(const std::function<bool()>& test) {
    for (int i = 0; i < 100; ++i) {
        if (test()) return true;
        std::this_thread::sleep_for(std::chrono::milliseconds(50));
    }
    return test();
}

static std::vector<std::string> feed(LineAssembler& a, std::string_view bytes, std::int64_t ms = 0) {
    std::vector<std::string> out;
    a.feed(bytes, ms, out);
    return out;
}

static std::string text(const std::string& line) { return line.substr(25); }

static void testMappings() {
    current = "mappings";
    std::string why;
    auto m = parseMapping("4-1 /dev/ttyAMA0   # the jig head", why);
    CHECK(m && m->port == "4-1" && m->tty == "/dev/ttyAMA0" && m->baud == 115200);
    m = parseMapping("1-1.2.3 /dev/ttyUSB0 921600", why);
    CHECK(m && m->port == "1-1.2.3" && m->baud == 921600);
    CHECK(!parseMapping("   # nothing", why) && why.empty());
    for (const char* bad : {"4-1", "4-* /dev/ttyAMA0", "4-1 ttyAMA0", "4-1 /dev/../etc/passwd",
                            "4-1 /dev/ttyAMA0 12345", "4-1 /dev/ttyAMA0 115200 extra", "4- /dev/ttyAMA0"}) {
        why.clear();
        CHECK(!parseMapping(bad, why) && !why.empty());
    }

    fs::path d = scratch();
    put(d / "vendor/50-jig.conf", "4-1 /dev/ttyAMA0\n");
    put(d / "vendor/60-bench.conf", "1-1 /dev/ttyUSB0\nnonsense\n");
    put(d / "vendor/README", "4-2 /dev/ttyAMA1\n");
    // Same name as a vendor file: replaces it. An empty one masks it.
    put(d / "local/60-bench.conf", "1-2 /dev/ttyUSB1 57600\n");
    std::vector<std::string> problems;
    auto all = readMappings(d / "vendor", d / "local", problems);
    CHECK(all.size() == 2);
    CHECK(all.size() == 2 && all[0].port == "4-1" && all[1].port == "1-2" && all[1].baud == 57600);
    CHECK(problems.empty());
    put(d / "local/50-jig.conf", "");
    put(d / "local/70-dup.conf", "1-2 /dev/ttyUSB9\n3-1 /dev/ttyUSB1\nnonsense\n");
    problems.clear();
    all = readMappings(d / "vendor", d / "local", problems);
    CHECK(all.size() == 1 && all[0].port == "1-2");
    CHECK(problems.size() == 3);
    problems.clear();
    CHECK(readMappings(d / "absent", d / "absent2", problems).empty() && problems.empty());
    fs::remove_all(d);
}

static void testTimestamps() {
    current = "timestamps";
    CHECK(timestamp(0) == "1970-01-01T00:00:00.000Z");
    CHECK(timestamp(1793802489123) == "2026-11-04T14:28:09.123Z");
    CHECK(timestamp(nowMs()).size() == 24);
}

static void testLines() {
    current = "lines";
    LineAssembler a;
    auto out = feed(a, "  5.94 RPi: BOOTSYS\r\n\r\n\n", 1000);
    CHECK(out.size() == 1 && out[0] == "1970-01-01T00:00:01.000Z   5.94 RPi: BOOTSYS");

    // What the gadget printed on the jig, escapes split across reads.
    out = feed(a, "\x1b[!p\x1b]104\x07\x1b[?7", 2000);
    CHECK(out.empty());
    out = feed(a, "h[    8.928850] fastbootd: io_uring request failed\n", 2100);
    CHECK(out.size() == 1 && text(out[0]) == "[    8.928850] fastbootd: io_uring request failed");
    // Timestamped from the line's first printed byte.
    CHECK(out.size() == 1 && out[0].substr(0, 24) == "1970-01-01T00:00:02.100Z");

    // An OSC left unterminated does not swallow what follows.
    out = feed(a, "\x1b]104\x1b[?7hkept\n");
    CHECK(out.size() == 1 && text(out[0]) == "kept");
    // ST-terminated OSC, a charset designation, other controls, DEL.
    out = feed(a, "\x1b]0;title\x1b\\a\x1b(Bb\x01\x08\x7f" "c\td\n");
    CHECK(out.size() == 1 && text(out[0]) == "abc\td");

    out = feed(a, std::string(LineAssembler::MAX_LINE + 10, 'x') + "\n");
    CHECK(out.size() == 2 && text(out[0]).size() == LineAssembler::MAX_LINE && text(out[1]).size() == 10);

    // A prompt with no newline is emitted once the board goes quiet.
    out = feed(a, "login: ", 5000);
    CHECK(out.empty());
    a.flushIdle(5500, 1000, out);
    CHECK(out.empty());
    a.flushIdle(6000, 1000, out);
    CHECK(out.size() == 1 && text(out[0]) == "login: ");
}

static void testWindows() {
    current = "windows";
    const fs::path root = "/var/log/rpi-sb-provisioner";
    auto w = parseWindow("start=2026-11-04T14:38:07.000Z\nlog=/var/log/rpi-sb-provisioner/6b1d1c93/uart.log\n", root);
    CHECK(w && w->end.empty() && w->log == root / "6b1d1c93/uart.log");
    CHECK(w && !inWindow(*w, "2026-11-04T14:38:06.999Z") && inWindow(*w, "2026-11-04T14:38:07.000Z"));
    CHECK(w && inWindow(*w, "2030-01-01T00:00:00.000Z"));
    w = parseWindow("start=2026-11-04T14:38:07.000Z\nend=2026-11-04T14:40:00.000Z\n"
                    "log=/var/log/rpi-sb-provisioner/4-1/uart.log\n", root);
    CHECK(w && inWindow(*w, "2026-11-04T14:40:15.000Z") && !inWindow(*w, "2026-11-04T14:40:15.001Z"));
    for (const char* bad : {"log=/var/log/rpi-sb-provisioner/x/uart.log\n",
                            "start=yesterday\nlog=/var/log/rpi-sb-provisioner/x/uart.log\n",
                            "start=2026-11-04T14:38:07.000Z\n",
                            "start=2026-11-04T14:38:07.000Z\nlog=/etc/passwd\n",
                            "start=2026-11-04T14:38:07.000Z\nlog=/var/log/rpi-sb-provisioner/../../etc/x\n",
                            "start=2026-11-04T14:38:07.000Z\nlog=/var/log/rpi-sb-provisioner\n",
                            "start=2026-11-04T14:38:07.000Z\nlog=relative/uart.log\n",
                            "start=2026-11-04T14:38:07.000Z\nend=soon\nlog=/var/log/rpi-sb-provisioner/x/uart.log\n"}) {
        CHECK(!parseWindow(bad, root));
    }

    fs::path d = scratch();
    put(d / "4-1.log.1", "2026-11-04T14:38:00.000Z old\n2026-11-04T14:38:08.000Z rotated\n");
    put(d / "4-1.log", "2026-11-04T14:38:09.000Z current\nshort\n");
    w = parseWindow("start=2026-11-04T14:38:07.000Z\nlog=/var/log/rpi-sb-provisioner/x/uart.log\n", root);
    CHECK(w && linesInWindow(*w, d / "4-1.log") ==
                   "2026-11-04T14:38:08.000Z rotated\n2026-11-04T14:38:09.000Z current\n");
    fs::remove_all(d);
}

// The daemon, run with its directories moved into a scratch tree.
struct Daemon {
    pid_t pid = -1;
    int err = -1;
    std::string said;

    void start(const std::string& exe, const fs::path& d) {
        int p[2];
        if (pipe(p) != 0) return;
        pid = fork();
        if (pid == 0) {
            dup2(p[1], 2);
            setenv("RPI_SB_UART_VENDOR_DIR", (d / "vendor").c_str(), 1);
            setenv("RPI_SB_UART_LOCAL_DIR", (d / "local").c_str(), 1);
            setenv("RPI_SB_UART_LOG_DIR", (d / "log/uart").c_str(), 1);
            setenv("RPI_SB_UART_WINDOW_DIR", (d / "run").c_str(), 1);
            setenv("RPI_SB_LOG_ROOT", (d / "log").c_str(), 1);
            execl(exe.c_str(), exe.c_str(), nullptr);
            _exit(127);
        }
        close(p[1]);
        err = p[0];
        fcntl(err, F_SETFL, O_NONBLOCK);
    }

    std::string stderrText() {
        char buf[512];
        for (ssize_t n; (n = read(err, buf, sizeof buf)) > 0;) said.append(buf, static_cast<std::size_t>(n));
        return said;
    }

    int stop() {
        int status = -1;
        kill(pid, SIGTERM);
        waitpid(pid, &status, 0);
        stderrText();
        close(err);
        return WIFEXITED(status) ? WEXITSTATUS(status) : -1;
    }
};

static void testDaemon(const std::string& exe) {
    current = "daemon";
    fs::path d = scratch();

    // Nothing mapped: says so and exits cleanly, so the unit does not restart.
    Daemon idle;
    idle.start(exe, d);
    int status = -1;
    waitpid(idle.pid, &status, 0);
    CHECK(WIFEXITED(status) && WEXITSTATUS(status) == 0);
    CHECK(idle.stderrText().find("nothing to capture") != std::string::npos);
    close(idle.err);

    int master = -1, slave = -1;
    char name[128];
    if (openpty(&master, &slave, name, nullptr, nullptr) != 0) {
        ++failures;
        std::cerr << current << ": openpty failed\n";
        return;
    }
    put(d / "vendor/50-jig.conf", std::string("4-1 ") + name + "\n");
    const fs::path portLog = d / "log/uart/4-1.log";
    const fs::path window = d / "run/4-1.window";
    const fs::path deviceLog = d / "log/6b1d1c93/uart.log";
    auto say = [&](const std::string& s) { CHECK(write(master, s.data(), s.size()) == static_cast<ssize_t>(s.size())); };

    Daemon daemon;
    daemon.start(exe, d);
    CHECK(eventually([&] { return daemon.stderrText().find("capturing at 115200") != std::string::npos; }));

    say("  5.94 RPi: BOOTSYS release\r\n");
    CHECK(eventually([&] { return get(portLog).find("RPi: BOOTSYS release") != std::string::npos; }));
    CHECK(!fs::exists(deviceLog));

    // A window opened after the board started still gets what came before it.
    put(window, "start=" + timestamp(nowMs() - 60000) + "\nlog=" + deviceLog.string() + "\n");
    CHECK(eventually([&] { return get(deviceLog).find("RPi: BOOTSYS release") != std::string::npos; }));
    say("\x1b[!p\x1b]104\x07\x1b[?7h[    8.928850] fastbootd: Couldn't read command\r\n");
    CHECK(eventually([&] { return get(deviceLog).find("] fastbootd: Couldn't read command\n") != std::string::npos; }));
    CHECK(get(deviceLog).find('\x1b') == std::string::npos);
    say("login: ");
    CHECK(eventually([&] { return get(deviceLog).find(" login: \n") != std::string::npos; }));

    // A restart rebuilds the device log from the port's: nothing lost or doubled.
    CHECK(daemon.stop() == 0);
    daemon = Daemon{};
    daemon.start(exe, d);
    CHECK(eventually([&] { return daemon.stderrText().find("copying into") != std::string::npos; }));
    say("after restart\n");
    CHECK(eventually([&] { return get(deviceLog).find("after restart") != std::string::npos; }));
    CHECK(count(get(deviceLog), "RPi: BOOTSYS release") == 1);
    CHECK(count(get(deviceLog), "Couldn't read command") == 1);

    // Ended longer ago than the tail: the port's log carries on, the device's stops.
    put(window, "start=" + timestamp(nowMs() - 60000) + "\nend=" + timestamp(nowMs() - 20000) +
                    "\nlog=" + deviceLog.string() + "\n");
    CHECK(eventually([&] { return daemon.stderrText().find("copying into") != std::string::npos; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    say("next board\n");
    CHECK(eventually([&] { return get(portLog).find("next board") != std::string::npos; }));
    std::this_thread::sleep_for(std::chrono::milliseconds(600));
    CHECK(get(deviceLog).find("next board") == std::string::npos);

    // A window pointing outside the log root is refused.
    put(window, "start=" + timestamp(nowMs()) + "\nlog=" + (d / "elsewhere.log").string() + "\n");
    CHECK(eventually([&] { return daemon.stderrText().find("ignoring") != std::string::npos; }));
    say("not copied\n");
    CHECK(eventually([&] { return get(portLog).find("not copied") != std::string::npos; }));
    CHECK(!fs::exists(d / "elsewhere.log"));

    CHECK(daemon.stop() == 0);
    close(master);
    close(slave);
    fs::remove_all(d);
}

int main(int argc, char** argv) {
    testMappings();
    testTimestamps();
    testLines();
    testWindows();
    if (argc > 1) testDaemon(argv[1]);
    else std::cerr << "daemon: skipped, no rpi-sb-uart-capture given\n";
    if (failures) {
        std::cerr << failures << " check(s) failed\n";
        return 1;
    }
    std::cout << "uartcapture: all checks passed\n";
    return 0;
}
