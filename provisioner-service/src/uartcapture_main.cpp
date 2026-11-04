// rpi-sb-uart-capture: keeps a log of the serial console of the device on
// each USB port that uart.d maps to a UART, and copies each line into the log
// of the device the provisioning scripts have put on that port.
//
//   uart.d/*.conf          "<usb-port> <tty> [baud]", read once at start
//   <log dir>/<port>.log   every line from the port, rotated to .1 at 8 MiB
//   <window dir>/<port>.window
//                          written by the scripts: start=, log= and, once the
//                          device is done, end=. On a new window the device
//                          log is rebuilt from the port's log, so a restart of
//                          this service loses nothing already captured.
//
// Directories can be moved with RPI_SB_UART_VENDOR_DIR, RPI_SB_UART_LOCAL_DIR,
// RPI_SB_UART_LOG_DIR, RPI_SB_UART_WINDOW_DIR and RPI_SB_LOG_ROOT, for tests.
//
// The UART is opened read-only and never written: its TX reaches the board.

#include "uartcapture.h"

#include <cerrno>
#include <csignal>
#include <cstring>
#include <fcntl.h>
#include <fstream>
#include <iostream>
#include <map>
#include <optional>
#include <poll.h>
#include <sstream>
#include <sys/stat.h>
#include <termios.h>
#include <unistd.h>

namespace fs = std::filesystem;
using namespace provisioner::uartcapture;

namespace {
    constexpr off_t ROTATE_AT = 8 * 1024 * 1024;
    constexpr std::int64_t RETRY_MS = 5000;
    constexpr std::int64_t IDLE_MS = 1000;

    volatile std::sig_atomic_t stopping = 0;

    fs::path env(const char* name, const char* fallback) {
        const char* v = std::getenv(name);
        return (v && *v) ? v : fallback;
    }

    speed_t speedFor(unsigned baud) {
        static const std::map<unsigned, speed_t> speeds = {
            {9600, B9600}, {19200, B19200}, {38400, B38400}, {57600, B57600},
            {115200, B115200}, {230400, B230400}, {460800, B460800}, {921600, B921600},
            {1000000, B1000000}, {1500000, B1500000}, {3000000, B3000000},
        };
        return speeds.at(baud);
    }

    bool writeAll(int fd, std::string_view data) {
        while (!data.empty()) {
            ssize_t n = ::write(fd, data.data(), data.size());
            if (n < 0 && errno == EINTR) continue;
            if (n <= 0) return false;
            data.remove_prefix(static_cast<std::size_t>(n));
        }
        return true;
    }

    int openAppend(const fs::path& p) {
        return ::open(p.c_str(), O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC, 0644);
    }

    struct Port {
        Mapping map;
        fs::path log;
        fs::path windowFile;
        int tty = -1;
        int logFd = -1;
        std::int64_t retryAt = 0;
        std::string lastError;
        LineAssembler lines;
        bool dirty = false;

        // The window last read, and the device log it feeds.
        struct stat seen{};
        bool haveSeen = false;
        std::optional<Window> window;
        int deviceFd = -1;

        void say(const std::string& what) {
            std::cerr << map.port << " (" << map.tty << "): " << what << std::endl;
        }

        void openTty(std::int64_t now) {
            int fd = ::open(map.tty.c_str(), O_RDONLY | O_NOCTTY | O_NONBLOCK | O_CLOEXEC);
            termios t{};
            std::string why;
            if (fd < 0) {
                why = std::string("cannot open: ") + std::strerror(errno);
            } else if (tcgetattr(fd, &t) != 0) {
                why = std::string("cannot read its settings: ") + std::strerror(errno);
            } else {
                cfmakeraw(&t);
                t.c_cflag |= CLOCAL | CREAD;
                t.c_cflag &= ~CRTSCTS;
                t.c_iflag |= IGNBRK | IGNPAR;
                cfsetispeed(&t, speedFor(map.baud));
                cfsetospeed(&t, speedFor(map.baud));
                if (tcsetattr(fd, TCSANOW, &t) != 0) why = std::string("cannot configure: ") + std::strerror(errno);
            }
            if (!why.empty()) {
                if (fd >= 0) ::close(fd);
                if (why != lastError) say(why + "; retrying every " + std::to_string(RETRY_MS / 1000) + " s");
                lastError = why;
                retryAt = now + RETRY_MS;
                return;
            }
            tty = fd;
            lastError.clear();
            say("capturing at " + std::to_string(map.baud) + " baud into " + log.string());
        }

        void closeTty(std::int64_t now, const std::string& why) {
            ::close(tty);
            tty = -1;
            retryAt = now + RETRY_MS;
            say(why);
        }

        void closeDevice() {
            if (deviceFd >= 0) ::close(deviceFd);
            deviceFd = -1;
        }

        // Rebuilds the device log from the port's log, durably, then appends.
        void startDevice(const Window& w) {
            closeDevice();
            std::error_code ec;
            fs::create_directories(w.log.parent_path(), ec);
            fs::path tmp = w.log.string() + ".tmp";
            int fd = ::open(tmp.c_str(), O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
            bool ok = fd >= 0 && writeAll(fd, linesInWindow(w, log)) && ::fsync(fd) == 0;
            if (fd >= 0) ::close(fd);
            if (!ok || ::rename(tmp.c_str(), w.log.c_str()) != 0) {
                say("cannot write " + w.log.string() + ": " + std::strerror(errno));
                ::unlink(tmp.c_str());
                return;
            }
            deviceFd = openAppend(w.log);
            say("copying into " + w.log.string() + " from " + w.start);
        }

        void refreshWindow(const fs::path& logRoot) {
            struct stat st{};
            if (::stat(windowFile.c_str(), &st) != 0) {
                if (window) say("window closed");
                window.reset();
                haveSeen = false;
                closeDevice();
                return;
            }
            if (haveSeen && st.st_ino == seen.st_ino && st.st_size == seen.st_size &&
                st.st_mtim.tv_sec == seen.st_mtim.tv_sec && st.st_mtim.tv_nsec == seen.st_mtim.tv_nsec)
                return;
            seen = st;
            haveSeen = true;
            std::ifstream in(windowFile);
            std::stringstream text;
            text << in.rdbuf();
            auto w = parseWindow(text.str(), logRoot);
            if (!w) {
                say("ignoring " + windowFile.string() + ": it needs start= and log= under " + logRoot.string());
                window.reset();
                closeDevice();
                return;
            }
            bool fresh = !window || window->start != w->start || window->log != w->log;
            window = w;
            if (fresh) startDevice(*w);
        }

        void rotateIfNeeded() {
            struct stat st{};
            if (::fstat(logFd, &st) != 0 || st.st_size < ROTATE_AT) return;
            fs::path old = log.string() + ".1";
            ::rename(log.c_str(), old.c_str());
            ::close(logFd);
            logFd = openAppend(log);
        }

        void write(const std::vector<std::string>& out) {
            for (const auto& line : out) {
                rotateIfNeeded();
                writeAll(logFd, line + "\n");
                if (deviceFd >= 0 && window && inWindow(*window, std::string_view(line).substr(0, 24)))
                    writeAll(deviceFd, line + "\n");
                dirty = true;
            }
        }

        void sync() {
            if (!dirty) return;
            ::fdatasync(logFd);
            if (deviceFd >= 0) ::fdatasync(deviceFd);
            dirty = false;
        }
    };

    void onSignal(int) { stopping = 1; }
}

int main() {
    const fs::path vendorDir = env("RPI_SB_UART_VENDOR_DIR", "/usr/share/rpi-sb-provisioner/uart.d");
    const fs::path localDir = env("RPI_SB_UART_LOCAL_DIR", "/etc/rpi-sb-provisioner/uart.d");
    const fs::path logDir = env("RPI_SB_UART_LOG_DIR", "/var/log/rpi-sb-provisioner/uart");
    const fs::path windowDir = env("RPI_SB_UART_WINDOW_DIR", "/run/rpi-sb-provisioner/uart");
    const fs::path logRoot = env("RPI_SB_LOG_ROOT", "/var/log/rpi-sb-provisioner");

    std::vector<std::string> problems;
    auto mappings = readMappings(vendorDir, localDir, problems);
    for (const auto& p : problems) std::cerr << p << std::endl;
    if (mappings.empty()) {
        std::cerr << "No port is mapped to a UART in " << vendorDir.string() << " or " << localDir.string()
                  << "; nothing to capture." << std::endl;
        return 0;
    }

    std::error_code ec;
    fs::create_directories(logDir, ec);
    fs::create_directories(windowDir, ec);

    std::vector<Port> ports;
    for (const auto& m : mappings) {
        Port p;
        p.map = m;
        p.log = logDir / (m.port + ".log");
        p.windowFile = windowDir / (m.port + ".window");
        p.logFd = openAppend(p.log);
        if (p.logFd < 0) {
            std::cerr << "Cannot open " << p.log.string() << ": " << std::strerror(errno) << std::endl;
            return 1;
        }
        ports.push_back(std::move(p));
    }

    struct sigaction sa{};
    sa.sa_handler = onSignal;
    sigaction(SIGTERM, &sa, nullptr);
    sigaction(SIGINT, &sa, nullptr);

    std::vector<pollfd> fds;
    std::vector<Port*> owners;
    std::string buf(4096, '\0');
    while (!stopping) {
        std::int64_t now = nowMs();
        fds.clear();
        owners.clear();
        for (auto& p : ports) {
            if (p.tty < 0 && now >= p.retryAt) p.openTty(now);
            if (p.tty >= 0) {
                fds.push_back({p.tty, POLLIN, 0});
                owners.push_back(&p);
            }
        }
        int n = ::poll(fds.data(), fds.size(), 250);
        if (n < 0 && errno != EINTR) {
            std::cerr << "poll: " << std::strerror(errno) << std::endl;
            return 1;
        }
        now = nowMs();
        for (std::size_t i = 0; n > 0 && i < fds.size(); ++i) {
            Port& p = *owners[i];
            if (!(fds[i].revents & (POLLIN | POLLHUP | POLLERR))) continue;
            ssize_t got = ::read(p.tty, buf.data(), buf.size());
            if (got > 0) {
                p.refreshWindow(logRoot);
                std::vector<std::string> out;
                p.lines.feed(std::string_view(buf.data(), static_cast<std::size_t>(got)), now, out);
                p.write(out);
            } else if (got == 0 || (errno != EAGAIN && errno != EINTR)) {
                p.closeTty(now, got == 0 ? "closed" : std::string("read failed: ") + std::strerror(errno));
            }
        }
        for (auto& p : ports) {
            p.refreshWindow(logRoot);
            std::vector<std::string> out;
            p.lines.flushIdle(now, IDLE_MS, out);
            p.write(out);
            p.sync();
        }
    }
    for (auto& p : ports) {
        std::vector<std::string> out;
        p.lines.flushIdle(nowMs(), 0, out);
        p.write(out);
        p.sync();
    }
    return 0;
}
