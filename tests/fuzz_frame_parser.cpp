#include <cstddef>
#include <cstdint>
#include <span>

#include "ttg/parser.hpp"

// libFuzzer entry point. Built with -fsanitize=fuzzer,address,undefined on
// Linux/Clang (see .github/workflows/fuzzing.yml). The contract is simply: no
// input may crash, hang or trigger undefined behaviour. The parser must be
// total over all byte sequences.
extern "C" int LLVMFuzzerTestOneInput(const std::uint8_t* data, std::size_t size) {
    const auto result = ttg::parse_frame(std::span<const std::uint8_t>(data, size));
    (void)result;
    return 0;
}
