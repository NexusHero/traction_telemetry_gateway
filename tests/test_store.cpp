#include "ttg/telemetry_store.hpp"

#include <cstdint>

#include <gtest/gtest.h>

#include "ttg/frame.hpp"

namespace {

ttg::Frame frame_with(std::uint64_t timestamp_ms, std::initializer_list<ttg::ChannelValue> values) {
    ttg::Frame frame;
    frame.timestamp_ms = timestamp_ms;
    frame.channels.assign(values.begin(), values.end());
    return frame;
}

ttg::ChannelValue int_channel(std::uint16_t id, std::int32_t value) {
    ttg::ChannelValue c;
    c.id = id;
    c.type = ttg::ValueType::Int32;
    c.as_int = value;
    return c;
}

TEST(TelemetryStore, KeepsLatestValuePerChannel) {
    ttg::TelemetryStore store;
    store.ingest(frame_with(100, {int_channel(1, 10), int_channel(2, 20)}));
    store.ingest(frame_with(200, {int_channel(1, 11)}));

    const auto snap = store.snapshot();
    ASSERT_EQ(snap.size(), 2U);
    EXPECT_EQ(snap[0].id, 1);
    EXPECT_EQ(snap[0].as_int, 11);
    EXPECT_EQ(snap[0].updated_at_ms, 200U);
    EXPECT_EQ(snap[0].update_count, 2U);
    EXPECT_EQ(snap[1].id, 2);
    EXPECT_EQ(snap[1].update_count, 1U);
}

TEST(TelemetryStore, SnapshotIsSortedById) {
    ttg::TelemetryStore store;
    store.ingest(frame_with(1, {int_channel(30, 1), int_channel(10, 1), int_channel(20, 1)}));
    const auto snap = store.snapshot();
    ASSERT_EQ(snap.size(), 3U);
    EXPECT_EQ(snap[0].id, 10);
    EXPECT_EQ(snap[1].id, 20);
    EXPECT_EQ(snap[2].id, 30);
}

TEST(TelemetryStore, EnforcesChannelCapacity) {
    ttg::TelemetryStore store(2);
    store.ingest(frame_with(1, {int_channel(1, 1), int_channel(2, 1), int_channel(3, 1)}));
    const auto snap = store.snapshot();
    EXPECT_EQ(snap.size(), 2U);
    EXPECT_EQ(store.stats().channels_tracked, 2U);
}

TEST(TelemetryStore, CountsReceivedAndRejected) {
    ttg::TelemetryStore store;
    store.ingest(frame_with(1, {int_channel(1, 1)}));
    store.record_rejected();
    store.record_rejected();
    const auto stats = store.stats();
    EXPECT_EQ(stats.frames_received, 1U);
    EXPECT_EQ(stats.frames_rejected, 2U);
}

}  // namespace
