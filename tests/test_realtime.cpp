// Real-time properties of the parser, enforced as tests.
//
// A real-time path may allocate only a bounded number of times, with a bounded
// size, decided by configuration and never by the input: a heap allocation is
// an unbounded-latency call into the allocator (locks, page faults, mmap), and
// one whose size an attacker picks is a latency and a memory problem at once.
//
// The parser's current contract, checked here:
//   - a frame rejected on its header costs no allocation at all;
//   - any frame costs at most one allocation, of at most kMaxChannels entries.
// The one allocation is Frame::channels. Taking it to zero means a
// fixed-capacity container in Frame; when that happens, tighten kMaxAllocs to 0
// and this file is the gate that keeps it there.
//
// This is its own executable because it replaces the global operator new: the
// counting must see every allocation, and must not change how any other test
// allocates.

#include <cstddef>
#include <cstdint>
#include <cstdlib>
#include <new>
#include <vector>

#include <gtest/gtest.h>

#include "frame_builder.hpp"
#include "ttg/frame.hpp"
#include "ttg/parser.hpp"

namespace {

// Counted only while armed, and only on the arming thread: gtest and the
// frame builder allocate freely around the call under test.
thread_local bool t_armed = false;
thread_local std::size_t t_allocs = 0;
thread_local std::size_t t_bytes = 0;

void* counted_alloc(std::size_t size) {
    if (t_armed) {
        ++t_allocs;
        t_bytes += size;
    }
    // malloc(0) may return nullptr legitimately; operator new must not.
    if (void* p = std::malloc(size == 0 ? 1 : size)) {
        return p;
    }
    throw std::bad_alloc();
}

}  // namespace

// Every non-aligned form is replaced, the nothrow ones included: ASan ships its
// own definitions of all of them, and a mix (its nothrow new, this delete) is
// an alloc-dealloc mismatch it reports. The aligned forms stay ASan's/libstdc++'s
// as a matched set; the parser does not use over-aligned types.
// NOLINTBEGIN(misc-new-delete-overloads,cert-dcl54-cpp)
void* operator new(std::size_t size) { return counted_alloc(size); }
void* operator new[](std::size_t size) { return counted_alloc(size); }
void* operator new(std::size_t size, const std::nothrow_t& /*tag*/) noexcept {
    try {
        return counted_alloc(size);
    } catch (...) {
        return nullptr;
    }
}
void* operator new[](std::size_t size, const std::nothrow_t& tag) noexcept {
    return ::operator new(size, tag);
}
void operator delete(void* p) noexcept { std::free(p); }
void operator delete[](void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t /*size*/) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t /*size*/) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t& /*tag*/) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t& /*tag*/) noexcept { std::free(p); }
// NOLINTEND(misc-new-delete-overloads,cert-dcl54-cpp)

namespace {

using ttg::ChannelValue;
using ttg::MsgType;
using ttg::ParseStatus;
using ttg::ValueType;
using ttg::test::build_frame;

constexpr std::size_t kMaxAllocs = 1;
constexpr std::size_t kMaxBytes = ttg::kMaxChannels * sizeof(ChannelValue);

struct AllocStats {
    std::size_t allocs;
    std::size_t bytes;
    ParseStatus status;
};

// The result is destroyed outside the armed window on purpose: freeing is not
// what is being measured, and the frame's lifetime belongs to the caller.
AllocStats measure_parse(const std::vector<std::uint8_t>& bytes) {
    t_allocs = 0;
    t_bytes = 0;
    t_armed = true;
    const ttg::ParseResult result = ttg::parse_frame(bytes);
    t_armed = false;
    return AllocStats{t_allocs, t_bytes, result.status};
}

std::vector<ChannelValue> channels(std::size_t count, ValueType type = ValueType::Int32) {
    std::vector<ChannelValue> out(count);
    for (std::size_t i = 0; i < count; ++i) {
        out[i].id = static_cast<std::uint16_t>(i);
        out[i].type = type;
        out[i].as_int = static_cast<std::int32_t>(i);
    }
    return out;
}

TEST(RealtimeParser, CounterSeesAllocations) {
    // Guards the guard: if operator new were not replaced (a linker or
    // sanitizer runtime winning the symbol), every test below would pass by
    // counting nothing.
    // An explicit ::operator new call, because a new-expression whose result
    // is never used may be elided entirely (allowed since C++14, and Clang
    // does it at -O2).
    t_allocs = 0;
    t_armed = true;
    void* p = ::operator new(sizeof(int));
    t_armed = false;
    ::operator delete(p);
    EXPECT_EQ(t_allocs, 1U);
}

TEST(RealtimeParser, HeaderRejectsDoNotAllocate) {
    std::vector<std::uint8_t> too_short(4, 0);
    std::vector<std::uint8_t> bad_magic = build_frame(MsgType::Telemetry, 1, 1, channels(1));
    bad_magic[0] ^= 0xFFU;
    std::vector<std::uint8_t> bad_version = build_frame(MsgType::Telemetry, 1, 1, channels(1));
    bad_version[2] = 0x7F;
    std::vector<std::uint8_t> bad_type = build_frame(MsgType::Telemetry, 1, 1, channels(1));
    bad_type[3] = 0x7F;
    std::vector<std::uint8_t> truncated = build_frame(MsgType::Telemetry, 1, 1, channels(4));
    truncated.pop_back();
    const std::vector<std::uint8_t> bad_crc =
        build_frame(MsgType::Telemetry, 1, 1, channels(4), /*corrupt_crc=*/true);

    for (const auto& frame : {too_short, bad_magic, bad_version, bad_type, truncated, bad_crc}) {
        const AllocStats stats = measure_parse(frame);
        EXPECT_NE(stats.status, ParseStatus::Ok);
        EXPECT_EQ(stats.allocs, 0U) << "status " << ttg::to_string(stats.status);
    }
}

TEST(RealtimeParser, AllocationIsBoundedIndependentOfInput) {
    for (const std::size_t count :
         {std::size_t{0}, std::size_t{1}, std::size_t{17}, ttg::kMaxChannels}) {
        const auto frame = build_frame(MsgType::Telemetry, 1, 1, channels(count));
        const AllocStats stats = measure_parse(frame);
        ASSERT_EQ(stats.status, ParseStatus::Ok) << count << " channels";
        EXPECT_LE(stats.allocs, kMaxAllocs) << count << " channels";
        EXPECT_LE(stats.bytes, kMaxBytes) << count << " channels";
    }
}

TEST(RealtimeParser, RejectAfterReserveStaysWithinBound) {
    // A bad channel entry is detected after the channel vector is reserved, so
    // this is the one reject path that allocates. It must still be within the
    // same bound as a good frame.
    auto frame = build_frame(MsgType::Telemetry, 1, 1, channels(ttg::kMaxChannels));
    frame[ttg::kHeaderSize + 2] = 0x7F;  // value_type of the first entry
    // Recompute the CRC so the frame reaches the channel loop.
    frame.resize(frame.size() - ttg::kCrcSize);
    ttg::test::put_u16(frame, ttg::crc16_ccitt(frame));

    const AllocStats stats = measure_parse(frame);
    ASSERT_EQ(stats.status, ParseStatus::BadChannelEntry);
    EXPECT_LE(stats.allocs, kMaxAllocs);
    EXPECT_LE(stats.bytes, kMaxBytes);
}

}  // namespace
