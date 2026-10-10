#include <cstddef>
#include <cstdint>
#include <span>

#include "ttg/parser.hpp"

extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto result = ttg::parse_frame(std::span<const std::uint8_t>(data, size));
    (void)result;
    return 0;
}
