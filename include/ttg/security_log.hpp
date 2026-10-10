#pragma once

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <mutex>
#include <string_view>

namespace ttg {

class SecurityLog {
public:
    using Sink = std::function<void(std::string_view line)>;
    using Clock = std::function<std::chrono::steady_clock::time_point()>;

    SecurityLog() = default;
    explicit SecurityLog(Sink sink, std::size_t max_events_per_second = 50,
                         Clock clock = std::chrono::steady_clock::now);

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

}
