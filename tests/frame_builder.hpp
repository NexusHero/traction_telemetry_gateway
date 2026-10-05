#pragma once

#include <bit>
#include <cstdint>
#include <span>
#include <vector>

#include "ttg/frame.hpp"
#include "ttg/parser.hpp"

namespace ttg::test {

inline void put_u16(std::vector<std::uint8_t>& out, std::uint16_t v) {
    out.push_back(static_cast<std::uint8_t>((v >> 8U) & 0xFFU));
    out.push_back(static_cast<std::uint8_t>(v & 0xFFU));
}

inline void put_u32(std::vector<std::uint8_t>& out, std::uint32_t v) {
    for (int shift = 24; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((v >> static_cast<unsigned>(shift)) & 0xFFU));
    }
}

inline void put_u64(std::vector<std::uint8_t>& out, std::uint64_t v) {
    for (int shift = 56; shift >= 0; shift -= 8) {
        out.push_back(static_cast<std::uint8_t>((v >> static_cast<unsigned>(shift)) & 0xFFU));
    }
}

inline std::vector<std::uint8_t> build_frame(MsgType type, std::uint32_t sequence,
                                             std::uint64_t timestamp_ms,
                                             const std::vector<ChannelValue>& channels,
                                             bool corrupt_crc = false) {
    const auto payload_len = static_cast<std::uint16_t>(channels.size() * kChannelEntrySize);
    std::vector<std::uint8_t> out;
    put_u16(out, kMagic);
    out.push_back(kVersion);
    out.push_back(static_cast<std::uint8_t>(type));
    put_u32(out, sequence);
    put_u64(out, timestamp_ms);
    put_u16(out, payload_len);
    for (const ChannelValue& value : channels) {
        put_u16(out, value.id);
        out.push_back(static_cast<std::uint8_t>(value.type));
        out.push_back(0);
        const std::uint32_t raw = (value.type == ValueType::Float32)
                                      ? std::bit_cast<std::uint32_t>(value.as_float)
                                      : std::bit_cast<std::uint32_t>(value.as_int);
        put_u32(out, raw);
    }
    std::uint16_t crc = crc16_ccitt(out);
    if (corrupt_crc) {
        crc ^= 0xFFFFU;
    }
    put_u16(out, crc);
    return out;
}

inline std::vector<std::uint8_t> build_frame_raw(MsgType type, std::uint32_t sequence,
                                                 std::uint64_t timestamp_ms,
                                                 std::span<const std::uint8_t> payload) {
    std::vector<std::uint8_t> out;
    put_u16(out, kMagic);
    out.push_back(kVersion);
    out.push_back(static_cast<std::uint8_t>(type));
    put_u32(out, sequence);
    put_u64(out, timestamp_ms);
    put_u16(out, static_cast<std::uint16_t>(payload.size()));
    out.insert(out.end(), payload.begin(), payload.end());
    put_u16(out, crc16_ccitt(out));
    return out;
}

}  // namespace ttg::test
