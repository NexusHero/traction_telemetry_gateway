#include "ttg/parser.hpp"

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <vector>

#include <gtest/gtest.h>

#include "frame_builder.hpp"
#include "ttg/frame.hpp"

namespace {

using ttg::ChannelValue;
using ttg::MsgType;
using ttg::ParseStatus;
using ttg::ValueType;
using ttg::test::build_frame;
using ttg::test::build_frame_raw;

ChannelValue int_channel(std::uint16_t id, std::int32_t value) {
    ChannelValue c;
    c.id = id;
    c.type = ValueType::Int32;
    c.as_int = value;
    c.as_float = 0.0F;
    return c;
}

ChannelValue float_channel(std::uint16_t id, float value) {
    ChannelValue c;
    c.id = id;
    c.type = ValueType::Float32;
    c.as_int = 0;
    c.as_float = value;
    return c;
}

TEST(Parser, IntAndFloatRoundTrip) {
    const std::vector<ChannelValue> channels{int_channel(7, -12345), float_channel(9, 3.5F)};
    const auto bytes = build_frame(MsgType::Telemetry, 42, 1'700'000'000'000ULL, channels);
    const auto result = ttg::parse_frame(bytes);
    ASSERT_TRUE(result.ok()) << ttg::to_string(result.status);
    EXPECT_EQ(result.frame.sequence, 42U);
    EXPECT_EQ(result.frame.timestamp_ms, 1'700'000'000'000ULL);
    ASSERT_EQ(result.frame.channels.size(), 2U);
    EXPECT_EQ(result.frame.channels[0].id, 7);
    EXPECT_EQ(result.frame.channels[0].as_int, -12345);
    EXPECT_FLOAT_EQ(result.frame.channels[1].as_float, 3.5F);
}

TEST(Parser, EmptyPayloadIsValid) {
    const auto bytes = build_frame(MsgType::Heartbeat, 1, 0, {});
    const auto result = ttg::parse_frame(bytes);
    ASSERT_TRUE(result.ok()) << ttg::to_string(result.status);
    EXPECT_TRUE(result.frame.channels.empty());
    EXPECT_EQ(result.frame.msg_type, MsgType::Heartbeat);
}

TEST(Parser, TooShortRejected) {
    const std::vector<std::uint8_t> bytes{0x54, 0x54, 0x01};
    EXPECT_EQ(ttg::parse_frame(bytes).status, ParseStatus::TooShort);
}

TEST(Parser, BadMagicRejected) {
    auto bytes = build_frame(MsgType::Telemetry, 1, 0, {});
    bytes[0] = 0x00;
    EXPECT_EQ(ttg::parse_frame(bytes).status, ParseStatus::BadMagic);
}

TEST(Parser, UnsupportedVersionRejected) {
    auto bytes = build_frame(MsgType::Telemetry, 1, 0, {});
    bytes[2] = 99;
    EXPECT_EQ(ttg::parse_frame(bytes).status, ParseStatus::UnsupportedVersion);
}

TEST(Parser, UnknownMessageTypeRejected) {
    auto bytes = build_frame(MsgType::Telemetry, 1, 0, {});
    bytes[3] = 0x7F;
    EXPECT_EQ(ttg::parse_frame(bytes).status, ParseStatus::UnknownMessageType);
}

TEST(Parser, PayloadLengthNotMultipleOfEntryRejected) {
    const std::vector<std::uint8_t> payload{0x01, 0x02, 0x03, 0x04, 0x05};
    const auto bytes = build_frame_raw(MsgType::Telemetry, 1, 0, payload);
    EXPECT_EQ(ttg::parse_frame(bytes).status, ParseStatus::BadChannelEntry);
}

TEST(Parser, OversizedPayloadRejected) {
    std::vector<std::uint8_t> payload(ttg::kMaxPayloadLen + ttg::kChannelEntrySize, 0);
    const auto bytes = build_frame_raw(MsgType::Telemetry, 1, 0, payload);
    EXPECT_EQ(ttg::parse_frame(bytes).status, ParseStatus::BadPayloadLength);
}

TEST(Parser, TruncatedPayloadRejected) {
    auto bytes = build_frame(MsgType::Telemetry, 1, 0, {int_channel(1, 1)});
    bytes.resize(bytes.size() - 4);
    EXPECT_EQ(ttg::parse_frame(bytes).status, ParseStatus::BadPayloadLength);
}

TEST(Parser, TrailingBytesRejected) {
    auto bytes = build_frame(MsgType::Telemetry, 1, 0, {});
    bytes.push_back(0x00);
    EXPECT_EQ(ttg::parse_frame(bytes).status, ParseStatus::BadPayloadLength);
}

TEST(Parser, CorruptedCrcRejected) {
    const auto bytes = build_frame(MsgType::Telemetry, 1, 0, {int_channel(1, 1)}, true);
    EXPECT_EQ(ttg::parse_frame(bytes).status, ParseStatus::BadCrc);
}

TEST(Parser, UnknownValueTypeRejected) {
    std::vector<std::uint8_t> payload(ttg::kChannelEntrySize, 0);
    payload[0] = 0x00;
    payload[1] = 0x01;
    payload[2] = 0x7F;
    const auto bytes = build_frame_raw(MsgType::Telemetry, 1, 0, payload);
    EXPECT_EQ(ttg::parse_frame(bytes).status, ParseStatus::BadChannelEntry);
}

TEST(Parser, NeverThrowsOnArbitraryInput) {
    std::uint32_t state = 0x12345678U;
    for (int iter = 0; iter < 20000; ++iter) {
        state = state * 1664525U + 1013904223U;
        const std::size_t len = state % 64U;
        std::vector<std::uint8_t> bytes(len);
        for (std::size_t i = 0; i < len; ++i) {
            state = state * 1664525U + 1013904223U;
            bytes[i] = static_cast<std::uint8_t>(state & 0xFFU);
        }
        EXPECT_NO_THROW({ (void)ttg::parse_frame(bytes); });
    }
}

TEST(Parser, ReplaysCheckedInCorpus) {
    namespace fs = std::filesystem;
    const fs::path dir{TTG_CORPUS_DIR};
    ASSERT_TRUE(fs::is_directory(dir)) << dir;

    std::size_t replayed = 0;
    for (const auto& entry : fs::directory_iterator(dir)) {
        if (!entry.is_regular_file()) {
            continue;
        }
        std::ifstream in(entry.path(), std::ios::binary);
        const std::vector<std::uint8_t> bytes{std::istreambuf_iterator<char>(in),
                                              std::istreambuf_iterator<char>()};
        const auto result = ttg::parse_frame(bytes);
        if (!result.ok()) {
            EXPECT_TRUE(result.frame.channels.empty()) << entry.path();
        }
        ++replayed;
    }
    EXPECT_GT(replayed, 0U) << "empty corpus directory: " << dir;
}

}
