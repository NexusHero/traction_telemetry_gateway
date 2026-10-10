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

thread_local bool t_armed = false;
thread_local std::size_t t_allocs = 0;
thread_local std::size_t t_bytes = 0;

void* counted_alloc(std::size_t size) {
    if (t_armed) {
        ++t_allocs;
        t_bytes += size;
    }
    if (void* p = std::malloc(size == 0 ? 1 : size)) {
        return p;
    }
    throw std::bad_alloc();
}

}

// NOLINTBEGIN(misc-new-delete-overloads,cert-dcl54-cpp)
void* operator new(std::size_t size) { return counted_alloc(size); }
void* operator new[](std::size_t size) { return counted_alloc(size); }
void* operator new(std::size_t size, const std::nothrow_t&) noexcept {
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
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete[](void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, const std::nothrow_t&) noexcept { std::free(p); }
void operator delete[](void* p, const std::nothrow_t&) noexcept { std::free(p); }
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
        build_frame(MsgType::Telemetry, 1, 1, channels(4), true);

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
    auto frame = build_frame(MsgType::Telemetry, 1, 1, channels(ttg::kMaxChannels));
    frame[ttg::kHeaderSize + 2] = 0x7F;
    frame.resize(frame.size() - ttg::kCrcSize);
    ttg::test::put_u16(frame, ttg::crc16_ccitt(frame));

    const AllocStats stats = measure_parse(frame);
    ASSERT_EQ(stats.status, ParseStatus::BadChannelEntry);
    EXPECT_LE(stats.allocs, kMaxAllocs);
    EXPECT_LE(stats.bytes, kMaxBytes);
}

}
