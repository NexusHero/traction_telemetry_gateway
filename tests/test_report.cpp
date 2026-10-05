#include "ttg/report.hpp"

#include <cstdint>

#include <gtest/gtest.h>

#include "ttg/frame.hpp"

TEST(Report, SerializesFrameToJson) {
    ttg::Frame frame;
    frame.msg_type = ttg::MsgType::Fault;
    frame.sequence = 5;
    frame.timestamp_ms = 42;
    ttg::ChannelValue value;
    value.id = 1;
    value.type = ttg::ValueType::Float32;
    value.as_float = 1.25F;
    frame.channels.push_back(value);

    const auto json = ttg::to_json(frame);
    EXPECT_EQ(json.at("msg_type"), "fault");
    EXPECT_EQ(json.at("sequence"), 5U);
    EXPECT_EQ(json.at("channel_count"), 1U);
    EXPECT_FLOAT_EQ(json.at("channels").at(0).at("value").get<float>(), 1.25F);
}

TEST(Report, SerializesStats) {
    ttg::StoreStats stats;
    stats.frames_received = 3;
    stats.frames_rejected = 1;
    stats.channels_tracked = 2;
    const auto json = ttg::to_json(stats);
    EXPECT_EQ(json.at("frames_received"), 3U);
    EXPECT_EQ(json.at("frames_rejected"), 1U);
}
