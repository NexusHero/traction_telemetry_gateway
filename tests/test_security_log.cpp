#include "ttg/security_log.hpp"

#include <chrono>
#include <string>
#include <string_view>
#include <vector>

#include <gtest/gtest.h>
#include <nlohmann/json.hpp>

namespace {

using std::chrono::milliseconds;
using std::chrono::steady_clock;

// A clock the test moves by hand, so the rate limit is tested without sleeping.
struct FakeClock {
    steady_clock::time_point now{steady_clock::time_point{} + std::chrono::hours(1)};
};

struct Capture {
    std::vector<std::string> lines;
};

ttg::SecurityLog make_log(Capture& capture, FakeClock& clock, std::size_t per_second) {
    return ttg::SecurityLog([&capture](std::string_view line) { capture.lines.emplace_back(line); },
                            per_second, [&clock] { return clock.now; });
}

TEST(SecurityLog, DisabledByDefault) {
    ttg::SecurityLog log;
    EXPECT_FALSE(log.enabled());
    log.record("auth_failure", "1.2.3.4", "missing_token");  // must not crash
}

TEST(SecurityLog, WritesOneJsonObjectPerEvent) {
    Capture capture;
    FakeClock clock;
    auto log = make_log(capture, clock, 10);
    log.record("auth_failure", "10.0.0.7", "invalid_token");

    ASSERT_EQ(capture.lines.size(), 1U);
    const auto event = nlohmann::json::parse(capture.lines[0]);
    EXPECT_EQ(event["event"], "auth_failure");
    EXPECT_EQ(event["remote"], "10.0.0.7");
    EXPECT_EQ(event["detail"], "invalid_token");
    EXPECT_TRUE(event.contains("ts_ms"));
}

TEST(SecurityLog, HostileFieldsCannotBreakTheLineFormat) {
    Capture capture;
    FakeClock clock;
    auto log = make_log(capture, clock, 10);
    log.record("auth_failure", "evil\n{\"event\":\"forged\"}", "x\"y");

    ASSERT_EQ(capture.lines.size(), 1U);
    EXPECT_EQ(capture.lines[0].find('\n'), std::string::npos);
    EXPECT_EQ(nlohmann::json::parse(capture.lines[0])["event"], "auth_failure");
}

TEST(SecurityLog, FloodIsCappedAndTheSuppressedCountReported) {
    Capture capture;
    FakeClock clock;
    auto log = make_log(capture, clock, 3);

    for (int i = 0; i < 10; ++i) {
        log.record("frame_rejected", "10.0.0.7", "bad_crc");
    }
    EXPECT_EQ(capture.lines.size(), 3U);  // the rest is counted, not written

    clock.now += milliseconds(1001);
    log.record("frame_rejected", "10.0.0.7", "bad_crc");

    ASSERT_EQ(capture.lines.size(), 5U);
    const auto summary = nlohmann::json::parse(capture.lines[3]);
    EXPECT_EQ(summary["event"], "events_suppressed");
    EXPECT_EQ(summary["count"], 7);
    EXPECT_EQ(nlohmann::json::parse(capture.lines[4])["event"], "frame_rejected");
}

}  // namespace
