#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string_view>

namespace ttg {

// Security-relevant events as JSON lines (one object per line) for a log
// collector to pick up from stderr: failed authentication, rejected frames,
// security-relevant configuration at startup. CRA Annex I, Part I (2)(l) asks
// for exactly this - recording internal activity relevant to security, with
// the possibility to opt out (main.cpp: TTG_SECURITY_LOG=off).
//
// Rate-limited, because the events it records are the ones an attacker can
// trigger at will: unbounded, a flood of bad frames would become a flood of
// log lines and turn the log into the denial-of-service vector. Events over
// the limit are counted, and the count is written as one "events_suppressed"
// line when the next window opens - the volume stays visible without the
// volume itself reaching the log.
class SecurityLog {
public:
    using Sink = std::function<void(std::string_view line)>;
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    // A default-constructed log is disabled and records nothing.
    SecurityLog() = default;
    explicit SecurityLog(Sink sink, std::size_t max_events_per_second = 50,
                         Clock clock = std::chrono::steady_clock::now);

    // remote is the peer address as the server saw it; detail is a short,
    // fixed token (a parse status, a reason) - never request content, so an
    // attacker cannot write arbitrary text into the log.
    void record(std::string_view event, std::string_view remote, std::string_view detail);

    [[nodiscard]] bool enabled() const noexcept { return static_cast<bool>(sink_); }

private:
    void emit(std::string_view line);

    Sink sink_;
    std::size_t max_per_window_{0};
    Clock clock_;

    std::mutex mutex_;
    std::chrono::steady_clock::time_point window_start_{};
    std::size_t in_window_{0};
    std::uint64_t suppressed_{0};
};

}  // namespace ttg
