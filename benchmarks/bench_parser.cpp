#include <benchmark/benchmark.h>

#include <cstdint>
#include <span>
#include <vector>

#include "frame_builder.hpp"
#include "memory_manager.hpp"
#include "ttg/parser.hpp"

namespace {

using ttg::ChannelValue;
using ttg::MsgType;
using ttg::ValueType;

ChannelValue make_int(std::uint16_t id, std::int32_t value) {
    ChannelValue c;
    c.id = id;
    c.type = ValueType::Int32;
    c.as_int = value;
    c.as_float = 0.0F;
    return c;
}

struct Inputs {
    std::vector<std::uint8_t> empty;
    std::vector<std::uint8_t> small;
    std::vector<std::uint8_t> max;
    std::vector<std::uint8_t> garbage;

    Inputs() {
        empty = ttg::test::build_frame(MsgType::Telemetry, 1, 0, {});

        small = ttg::test::build_frame(MsgType::Telemetry, 1, 0,
                                       {make_int(1, 10), make_int(2, 20), make_int(3, 30)});

        std::vector<ChannelValue> many;
        many.reserve(ttg::kMaxChannels);
        for (std::uint16_t i = 0; i < static_cast<std::uint16_t>(ttg::kMaxChannels); ++i) {
            many.push_back(make_int(i, static_cast<std::int32_t>(i)));
        }
        max = ttg::test::build_frame(MsgType::Telemetry, 1, 0, many);

        garbage = ttg::test::build_frame(MsgType::Telemetry, 1, 0, {}, true);
    }
};

const Inputs& inputs() {
    static const Inputs instance;
    return instance;
}

void parse(benchmark::State& state, const std::vector<std::uint8_t>& bytes) {
    const ttg::bench::AllocSnapshot before = ttg::bench::alloc_snapshot();
    for (auto _ : state) {
        const auto result = ttg::parse_frame(std::span<const std::uint8_t>(bytes));
        benchmark::DoNotOptimize(result);
    }
    ttg::bench::report_allocations(state, before);

    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(bytes.size()));
    state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()));
}

void BM_ParseEmpty(benchmark::State& state) { parse(state, inputs().empty); }
BENCHMARK(BM_ParseEmpty);

void BM_ParseSmall(benchmark::State& state) { parse(state, inputs().small); }
BENCHMARK(BM_ParseSmall);

void BM_ParseMax(benchmark::State& state) { parse(state, inputs().max); }
BENCHMARK(BM_ParseMax);

void BM_ParseRejectBadCrc(benchmark::State& state) { parse(state, inputs().garbage); }
BENCHMARK(BM_ParseRejectBadCrc);

void BM_Crc16(benchmark::State& state) {
    const auto& bytes = inputs().max;
    const ttg::bench::AllocSnapshot before = ttg::bench::alloc_snapshot();
    for (auto _ : state) {
        const std::uint16_t crc = ttg::crc16_ccitt(std::span<const std::uint8_t>(bytes));
        benchmark::DoNotOptimize(crc);
    }
    ttg::bench::report_allocations(state, before);
    state.SetBytesProcessed(static_cast<std::int64_t>(state.iterations()) *
                            static_cast<std::int64_t>(bytes.size()));
}
BENCHMARK(BM_Crc16);

}
