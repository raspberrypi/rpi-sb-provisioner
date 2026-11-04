#include "uartcapture.h"

#include <algorithm>
#include <cctype>
#include <ctime>
#include <fstream>
#include <map>
#include <set>
#include <sstream>

namespace fs = std::filesystem;

namespace provisioner::uartcapture {

    namespace {
        std::string_view trim(std::string_view s) {
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.front()))) s.remove_prefix(1);
            while (!s.empty() && std::isspace(static_cast<unsigned char>(s.back()))) s.remove_suffix(1);
            return s;
        }

        std::vector<std::string> words(std::string_view s) {
            std::vector<std::string> out;
            std::istringstream in{std::string(s)};
            for (std::string w; in >> w;) out.push_back(w);
            return out;
        }

        // The inverse of timestamp(); nullopt for anything else.
        std::optional<std::int64_t> parseTimestamp(std::string_view ts) {
            if (ts.size() != 24 || ts[10] != 'T' || ts[23] != 'Z') return std::nullopt;
            std::tm tm{};
            int ms = 0;
            if (std::sscanf(std::string(ts).c_str(), "%4d-%2d-%2dT%2d:%2d:%2d.%3dZ", &tm.tm_year, &tm.tm_mon,
                            &tm.tm_mday, &tm.tm_hour, &tm.tm_min, &tm.tm_sec, &ms) != 7)
                return std::nullopt;
            tm.tm_year -= 1900;
            tm.tm_mon -= 1;
            return static_cast<std::int64_t>(timegm(&tm)) * 1000 + ms;
        }

        const std::set<unsigned> BAUDS = {9600, 19200, 38400, 57600, 115200, 230400,
                                          460800, 921600, 1000000, 1500000, 3000000};
    }

    bool isSupportedBaud(unsigned baud) { return BAUDS.count(baud) != 0; }

    bool isPortPath(std::string_view s) {
        // <bus>-<port>[.<port>...]
        std::size_t i = 0;
        auto digits = [&] {
            std::size_t from = i;
            while (i < s.size() && std::isdigit(static_cast<unsigned char>(s[i]))) ++i;
            return i > from;
        };
        if (!digits() || i >= s.size() || s[i++] != '-' || !digits()) return false;
        while (i < s.size()) {
            if (s[i++] != '.' || !digits()) return false;
        }
        return true;
    }

    std::optional<Mapping> parseMapping(std::string_view line, std::string& why) {
        auto hash = line.find('#');
        if (hash != std::string_view::npos) line = line.substr(0, hash);
        auto w = words(trim(line));
        if (w.empty()) return std::nullopt;
        if (w.size() < 2 || w.size() > 3) {
            why = "expected \"<usb-port> <tty> [baud]\"";
            return std::nullopt;
        }
        Mapping m{w[0], w[1]};
        if (!isPortPath(m.port)) {
            why = "\"" + m.port + "\" is not a USB port path such as 1-1.2";
            return std::nullopt;
        }
        if (m.tty.rfind("/dev/", 0) != 0 || m.tty.find("..") != std::string::npos) {
            why = "\"" + m.tty + "\" is not a device under /dev";
            return std::nullopt;
        }
        if (w.size() == 3) {
            unsigned long baud = 0;
            try {
                std::size_t used = 0;
                baud = std::stoul(w[2], &used);
                if (used != w[2].size()) baud = 0;
            } catch (...) {}
            if (!isSupportedBaud(static_cast<unsigned>(baud))) {
                why = "\"" + w[2] + "\" is not a supported baud rate";
                return std::nullopt;
            }
            m.baud = static_cast<unsigned>(baud);
        }
        return m;
    }

    std::vector<Mapping> readMappings(const fs::path& vendorDir, const fs::path& localDir,
                                      std::vector<std::string>& problems) {
        std::map<std::string, fs::path> files;
        for (const auto& dir : {vendorDir, localDir}) {
            std::error_code ec;
            for (const auto& e : fs::directory_iterator(dir, ec)) {
                if (e.path().extension() == ".conf") files[e.path().filename().string()] = e.path();
            }
        }
        std::vector<Mapping> out;
        std::set<std::string> ports, ttys;
        for (const auto& [name, path] : files) {
            std::ifstream in(path);
            std::string line;
            for (int n = 1; std::getline(in, line); ++n) {
                std::string why;
                auto m = parseMapping(line, why);
                std::string where = path.string() + ":" + std::to_string(n) + ": ";
                if (!m) {
                    if (!why.empty()) problems.push_back(where + why);
                    continue;
                }
                if (ports.count(m->port) || ttys.count(m->tty)) {
                    problems.push_back(where + m->port + " or " + m->tty + " is already mapped");
                    continue;
                }
                ports.insert(m->port);
                ttys.insert(m->tty);
                out.push_back(*m);
            }
        }
        return out;
    }

    std::int64_t nowMs() {
        timespec ts{};
        clock_gettime(CLOCK_REALTIME, &ts);
        return static_cast<std::int64_t>(ts.tv_sec) * 1000 + ts.tv_nsec / 1000000;
    }

    std::string timestamp(std::int64_t ms) {
        std::time_t secs = static_cast<std::time_t>(ms / 1000);
        std::tm tm{};
        gmtime_r(&secs, &tm);
        char buf[64];
        std::snprintf(buf, sizeof buf, "%04d-%02d-%02dT%02d:%02d:%02d.%03dZ", tm.tm_year + 1900,
                      tm.tm_mon + 1, tm.tm_mday, tm.tm_hour, tm.tm_min, tm.tm_sec,
                      static_cast<int>(ms % 1000));
        return buf;
    }

    void LineAssembler::emit(std::vector<std::string>& out) {
        if (!trim(line_).empty()) out.push_back(timestamp(lineStart_) + " " + line_);
        line_.clear();
    }

    void LineAssembler::escape(unsigned char c) {
        if (c == '[') state_ = State::Csi;
        else if (c == ']') state_ = State::Osc;
        else if (c >= 0x20 && c <= 0x2f) state_ = State::EscIntermediate;
        else state_ = State::Text;
    }

    void LineAssembler::feed(std::string_view bytes, std::int64_t ms, std::vector<std::string>& out) {
        lastByte_ = ms;
        for (unsigned char c : bytes) {
            switch (state_) {
            case State::Text:
                if (c == '\n') {
                    emit(out);
                } else if (c == 0x1b) {
                    state_ = State::Esc;
                } else if (c == '\t' || c >= 0x20) {
                    if (c == 0x7f) break;
                    if (line_.empty()) lineStart_ = ms;
                    line_.push_back(static_cast<char>(c));
                    if (line_.size() >= MAX_LINE) emit(out);
                }
                break;
            case State::Esc:
                escape(c);
                break;
            case State::EscIntermediate:
                if (c < 0x20 || c > 0x2f) state_ = State::Text;
                break;
            case State::Csi:
                if (c < 0x20 || c > 0x3f) state_ = State::Text;
                break;
            case State::Osc:
                if (c == 0x07 || c == '\n') state_ = State::Text;
                else if (c == 0x1b) state_ = State::OscEsc;
                break;
            case State::OscEsc:
                // ST ends the OSC. Anything else began a new sequence, as when
                // a board leaves an OSC unterminated.
                if (c == '\\') state_ = State::Text;
                else escape(c);
                break;
            }
        }
    }

    void LineAssembler::flushIdle(std::int64_t ms, std::int64_t idleMs, std::vector<std::string>& out) {
        if (!line_.empty() && ms - lastByte_ >= idleMs) emit(out);
    }

    std::optional<Window> parseWindow(std::string_view text, const fs::path& logRoot) {
        Window w;
        std::istringstream in{std::string(text)};
        for (std::string line; std::getline(in, line);) {
            auto eq = line.find('=');
            if (eq == std::string::npos) continue;
            std::string key = line.substr(0, eq), value{trim(std::string_view(line).substr(eq + 1))};
            if (key == "start") w.start = value;
            else if (key == "end") w.end = value;
            else if (key == "log") w.log = value;
        }
        if (!parseTimestamp(w.start) || (!w.end.empty() && !parseTimestamp(w.end))) return std::nullopt;
        if (!w.log.is_absolute() || w.log.lexically_normal() != w.log) return std::nullopt;
        auto rel = w.log.lexically_relative(logRoot);
        if (rel.empty() || *rel.begin() == ".." || rel == ".") return std::nullopt;
        return w;
    }

    bool inWindow(const Window& w, std::string_view ts) {
        if (ts < std::string_view(w.start)) return false;
        if (w.end.empty()) return true;
        auto end = parseTimestamp(w.end);
        return end && ts <= std::string_view(timestamp(*end + Window::TAIL_MS));
    }

    std::string linesInWindow(const Window& w, const fs::path& portLog) {
        std::string out;
        for (const auto& p : {fs::path(portLog.string() + ".1"), portLog}) {
            std::ifstream in(p);
            for (std::string line; std::getline(in, line);) {
                if (line.size() > 24 && inWindow(w, std::string_view(line).substr(0, 24)))
                    out += line + "\n";
            }
        }
        return out;
    }

} // namespace provisioner::uartcapture
