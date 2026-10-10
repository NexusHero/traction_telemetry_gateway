#pragma once

#include <cstdint>
#include <span>

#include "ttg/frame.hpp"

namespace ttg {

enum class ParseStatus : std::uint8_t {
    Ok,
    TooShort,
    BadMagic,
    UnsupportedVersion,
    UnknownMessageType,
    BadPayloadLength,
    TooManyChannels,
    BadChannelEntry,
    BadCrc,
};

struct ParseResult {
    ParseStatus status{ParseStatus::TooShort};
    Frame frame{};

    [[nodiscard]] bool ok() const noexcept { return status == ParseStatus::Ok; }
};

[[nodiscard]] ParseResult parse_frame(std::span<const std::uint8_t> data);

[[nodiscard]] std::uint16_t crc16_ccitt(std::span<const std::uint8_t> data) noexcept;
[[nodiscard]] const char* to_string(ParseStatus status) noexcept;

}
