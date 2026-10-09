#include "ttg/parser.hpp"

#include <bit>
#include <cstring>

namespace ttg {
namespace {

// Bounds are guaranteed by the caller before these are used, but they take a
// span and an explicit offset so that a future refactor cannot silently read
// past the end.
std::uint16_t read_u16(std::span<const std::uint8_t> d, std::size_t off) noexcept {
    return static_cast<std::uint16_t>((static_cast<std::uint16_t>(d[off]) << 8U) |
                                      static_cast<std::uint16_t>(d[off + 1]));
}

std::uint32_t read_u32(std::span<const std::uint8_t> d, std::size_t off) noexcept {
    return (static_cast<std::uint32_t>(d[off]) << 24U) |
           (static_cast<std::uint32_t>(d[off + 1]) << 16U) |
           (static_cast<std::uint32_t>(d[off + 2]) << 8U) | static_cast<std::uint32_t>(d[off + 3]);
}

std::uint64_t read_u64(std::span<const std::uint8_t> d, std::size_t off) noexcept {
    std::uint64_t v = 0;
    for (std::size_t i = 0; i < 8; ++i) {
        v = (v << 8U) | static_cast<std::uint64_t>(d[off + i]);
    }
    return v;
}

bool is_known_msg_type(std::uint8_t raw) noexcept {
    switch (static_cast<MsgType>(raw)) {
    case MsgType::Telemetry:
    case MsgType::Heartbeat:
    case MsgType::Fault:
        return true;
    }
    return false;
}

}  // namespace

std::uint16_t crc16_ccitt(std::span<const std::uint8_t> data) noexcept {
    // Work in 32 bits so every intermediate stays unsigned and sign-conversion
    // free; the value is kept to 16 bits by masking each step.
    std::uint32_t crc = 0xFFFFU;
    for (std::uint8_t byte : data) {
        crc ^= static_cast<std::uint32_t>(byte) << 8U;
        for (int bit = 0; bit < 8; ++bit) {
            if ((crc & 0x8000U) != 0U) {
                crc = (crc << 1U) ^ 0x1021U;
            } else {
                crc = crc << 1U;
            }
            crc &= 0xFFFFU;
        }
    }
    return static_cast<std::uint16_t>(crc);
}

ParseResult parse_frame(std::span<const std::uint8_t> data) {
    ParseResult result;

    if (data.size() < kHeaderSize + kCrcSize) {
        result.status = ParseStatus::TooShort;
        return result;
    }

    if (read_u16(data, 0) != kMagic) {
        result.status = ParseStatus::BadMagic;
        return result;
    }

    if (data[2] != kVersion) {
        result.status = ParseStatus::UnsupportedVersion;
        return result;
    }

    if (!is_known_msg_type(data[3])) {
        result.status = ParseStatus::UnknownMessageType;
        return result;
    }

    const std::uint16_t payload_len = read_u16(data, 16);
    if (payload_len > kMaxPayloadLen) {
        result.status = ParseStatus::BadPayloadLength;
        return result;
    }
    if ((payload_len % kChannelEntrySize) != 0) {
        result.status = ParseStatus::BadChannelEntry;
        return result;
    }

    const std::size_t expected_size = kHeaderSize + payload_len + kCrcSize;
    if (data.size() != expected_size) {
        // Covers both a truncated frame and trailing garbage after the CRC.
        result.status = ParseStatus::BadPayloadLength;
        return result;
    }

    const std::size_t channel_count = payload_len / kChannelEntrySize;
    if (channel_count > kMaxChannels) {
        result.status = ParseStatus::TooManyChannels;
        return result;
    }

    const std::uint16_t expected_crc = read_u16(data, kHeaderSize + payload_len);
    const std::uint16_t actual_crc = crc16_ccitt(data.first(kHeaderSize + payload_len));
    if (expected_crc != actual_crc) {
        result.status = ParseStatus::BadCrc;
        return result;
    }

    Frame frame;
    frame.msg_type = static_cast<MsgType>(data[3]);
    frame.sequence = read_u32(data, 4);
    frame.timestamp_ms = read_u64(data, 8);
    frame.channels.reserve(channel_count);

    for (std::size_t i = 0; i < channel_count; ++i) {
        const std::size_t off = kHeaderSize + (i * kChannelEntrySize);
        const std::uint8_t raw_type = data[off + 2];
        if (raw_type != static_cast<std::uint8_t>(ValueType::Int32) &&
            raw_type != static_cast<std::uint8_t>(ValueType::Float32)) {
            result.status = ParseStatus::BadChannelEntry;
            return result;
        }

        ChannelValue value;
        value.id = read_u16(data, off);
        value.type = static_cast<ValueType>(raw_type);
        const std::uint32_t raw = read_u32(data, off + 4);
        value.as_int = std::bit_cast<std::int32_t>(raw);
        value.as_float = std::bit_cast<float>(raw);
        frame.channels.push_back(value);
    }

    result.status = ParseStatus::Ok;
    result.frame = std::move(frame);
    return result;
}

const char* to_string(ParseStatus status) noexcept {
    switch (status) {
    case ParseStatus::Ok:
        return "ok";
    case ParseStatus::TooShort:
        return "too_short";
    case ParseStatus::BadMagic:
        return "bad_magic";
    case ParseStatus::UnsupportedVersion:
        return "unsupported_version";
    case ParseStatus::UnknownMessageType:
        return "unknown_message_type";
    case ParseStatus::BadPayloadLength:
        return "bad_payload_length";
    case ParseStatus::TooManyChannels:
        return "too_many_channels";
    case ParseStatus::BadChannelEntry:
        return "bad_channel_entry";
    case ParseStatus::BadCrc:
        return "bad_crc";
    }
    return "unknown";
}

const char* to_string(MsgType type) noexcept {
    switch (type) {
    case MsgType::Telemetry:
        return "telemetry";
    case MsgType::Heartbeat:
        return "heartbeat";
    case MsgType::Fault:
        return "fault";
    }
    return "unknown";
}

const char* to_string(ValueType type) noexcept {
    switch (type) {
    case ValueType::Int32:
        return "int32";
    case ValueType::Float32:
        return "float32";
    }
    return "unknown";
}

}  // namespace ttg
