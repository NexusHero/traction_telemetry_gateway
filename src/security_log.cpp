#include "ttg/security_log.hpp"

#include <string>
#include <utility>

#include <nlohmann/json.hpp>

namespace ttg {
namespace {

std::int64_t unix_millis() {
    return std::chrono::duration_cast<std::chrono::milliseconds>(
               std::chrono::system_clock::now().time_since_epoch())
        .count();
}

}  // namespace

SecurityLog::SecurityLog(Sink sink, std::size_t max_events_per_second, Clock clock)
    : sink_(std::move(sink)), max_per_window_(max_events_per_second), clock_(std::move(clock)) {}

void SecurityLog::record(std::string_view event, std::string_view remote, std::string_view detail) {
    if (!sink_) {
        return;
    }
    const std::lock_guard<std::mutex> lock(mutex_);

    const auto now = clock_();
    if (now - window_start_ >= std::chrono::seconds(1)) {
        window_start_ = now;
        in_window_ = 0;
        if (suppressed_ > 0) {
            emit(nlohmann::json{
                {"ts_ms", unix_millis()}, {"event", "events_suppressed"}, {"count", suppressed_}}
                     .dump());
            suppressed_ = 0;
        }
    }
    if (in_window_ >= max_per_window_) {
        ++suppressed_;
        return;
    }
    ++in_window_;

    // dump() escapes every string, so even a hostile peer address cannot
    // break the one-object-per-line format.
    emit(nlohmann::json{{"ts_ms", unix_millis()},
                        {"event", std::string(event)},
                        {"remote", std::string(remote)},
                        {"detail", std::string(detail)}}
             .dump());
}

void SecurityLog::emit(std::string_view line) { sink_(line); }

}  // namespace ttg
