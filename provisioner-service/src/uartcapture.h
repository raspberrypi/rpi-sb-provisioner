#pragma once

// Capture of the serial console of the device on a USB port. A jig can wire a
// host UART to the console of the board in its head; uart.d maps the port to
// that UART. Every line the board prints is kept in a log for the port, and
// copied into the log of whichever device the provisioning scripts say is on
// the port, so a device's bootloader, kernel and fastbootd messages sit beside
// its other logs.
//
// The capture only ever reads: the host's TX reaches the board's console.
//
// Drogon-free, so uartcapture_test runs it without a station.

#include <cstdint>
#include <filesystem>
#include <optional>
#include <string>
#include <string_view>
#include <vector>

namespace provisioner::uartcapture {

    // One uart.d line: "<usb-port> <tty> [baud]".
    struct Mapping {
        std::string port;   // e.g. "4-1", as in usb-ports.d
        std::string tty;    // e.g. "/dev/ttyAMA0"
        unsigned baud = 115200;
    };

    // Reads every *.conf in the vendor and local directories, merged by
    // basename with the local copy winning, as usb-ports.d is. A port named
    // twice keeps its first mapping. Lines that do not parse are reported in
    // problems and skipped.
    std::vector<Mapping> readMappings(const std::filesystem::path& vendorDir,
                                      const std::filesystem::path& localDir,
                                      std::vector<std::string>& problems);

    // Parses one line, after comments are stripped. nullopt for a blank line;
    // a line that does not parse sets why.
    std::optional<Mapping> parseMapping(std::string_view line, std::string& why);

    bool isPortPath(std::string_view s);
    bool isSupportedBaud(unsigned baud);

    // "2026-11-04T14:38:09.123Z" for a CLOCK_REALTIME time in milliseconds.
    // Fixed width, so lines compare and sort as strings.
    std::string timestamp(std::int64_t ms);
    std::int64_t nowMs();

    // Splits the bytes a board sends into printable lines, dropping terminal
    // escape sequences, carriage returns and other control characters.
    class LineAssembler {
    public:
        static constexpr std::size_t MAX_LINE = 4096;

        // Feeds bytes that arrived at ms; complete lines are appended to out
        // as "<timestamp> <text>". Blank lines are dropped.
        void feed(std::string_view bytes, std::int64_t ms, std::vector<std::string>& out);

        // Emits a partial line, as for a prompt with no newline, once nothing
        // has arrived for idleMs.
        void flushIdle(std::int64_t ms, std::int64_t idleMs, std::vector<std::string>& out);

    private:
        enum class State { Text, Esc, EscIntermediate, Csi, Osc, OscEsc };
        State state_ = State::Text;
        std::string line_;
        std::int64_t lineStart_ = 0;
        std::int64_t lastByte_ = 0;
        void emit(std::vector<std::string>& out);
        void escape(unsigned char c);
    };

    // What the provisioning scripts write to <port>.window: which device's
    // log the port's lines go to, from when, and, once the device is done,
    // until when. Lines are still copied for TAIL_MS after the end, to catch
    // the board rebooting.
    struct Window {
        static constexpr std::int64_t TAIL_MS = 15000;
        std::string start;  // timestamp
        std::string end;    // timestamp, or "" while the device is in progress
        std::filesystem::path log;
    };

    // nullopt unless start and log are set and log is a file under logRoot.
    std::optional<Window> parseWindow(std::string_view text, const std::filesystem::path& logRoot);

    // Whether a line stamped ts belongs in the window.
    bool inWindow(const Window& w, std::string_view ts);

    // The lines of the port's log, and of its rotated copy, that belong in
    // the window, oldest first.
    std::string linesInWindow(const Window& w, const std::filesystem::path& portLog);

} // namespace provisioner::uartcapture
