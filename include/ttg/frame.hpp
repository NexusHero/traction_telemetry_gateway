#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace ttg {

inline constexpr std::uint16_t kMagic = 0x5454;
inline constexpr std::uint8_t kVersion = 1;
inline constexpr std::size_t kHeaderSize = 18;
inline constexpr std::size_t kCrcSize = 2;
inline constexpr std::size_t kChannelEntrySize = 8;
inline constexpr std::size_t kMaxPayloadLen = 1024;
inline constexpr std::size_t kMaxChannels = kMaxPayloadLen / kChannelEntrySize;

enum class MsgType : std::uint8_t {
    Telemetry = 0x01,
    Heartbeat = 0x02,
    Fault = 0x03,
};

enum class ValueType : std::uint8_t {
    Int32 = 0x00,
    Float32 = 0x01,
};

struct ChannelValue {
    std::uint16_t id{};
    ValueType type{ValueType::Int32};
    std::int32_t as_int{};
    float as_float{};
};

struct Frame {
    MsgType msg_type{MsgType::Telemetry};
    std::uint32_t sequence{};
    std::uint64_t timestamp_ms{};
    std::vector<ChannelValue> channels;
};

[[nodiscard]] const char* to_string(MsgType type) noexcept;
[[nodiscard]] const char* to_string(ValueType type) noexcept;

}
