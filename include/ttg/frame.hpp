#pragma once

#include <cstdint>
#include <span>
#include <vector>

namespace ttg {

// Wire format for the traction telemetry bus (TTB) frame.
//
//   offset  size  field
//   0       2     magic          0x5454 ("TT")
//   2       1     version        1
//   3       1     msg_type       ttg::MsgType
//   4       4     sequence       big endian uint32
//   8       8     timestamp_ms   big endian uint64
//   16      2     payload_len    big endian uint16, multiple of kChannelEntrySize
//   18      n     payload        n / 8 channel entries
//   18+n    2     crc16          CRC-16/CCITT-FALSE over bytes [0, 18+n)
//
// Channel entry (8 bytes):
//   0       2     channel_id     big endian uint16
//   2       1     value_type     ttg::ValueType
//   3       1     reserved       must be zero
//   4       4     value          int32 or IEEE-754 float32, big endian
//
// Every length field in this format is attacker-controlled: the parser is the
// primary trust boundary of the service and the target of the fuzzing harness.

inline constexpr std::uint16_t kMagic = 0x5454;  // "TT"
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

}  // namespace ttg
