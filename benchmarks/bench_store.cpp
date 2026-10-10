#include <benchmark/benchmark.h>

#include <cstdint>
#include <vector>

#include "frame_builder.hpp"
#include "memory_manager.hpp"
#include "ttg/frame.hpp"
#include "ttg/telemetry_store.hpp"

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

ttg::Frame make_frame(std::size_t channels) {
    std::vector<ChannelValue> values;
    values.reserve(channels);
    for (std::uint16_t i = 0; i < channels; ++i) {
        values.push_back(make_int(i, static_cast<std::int32_t>(i)));
    }
    const auto bytes = ttg::test::build_frame(MsgType::Telemetry, 1, 0, values);
    return ttg::parse_frame(bytes).frame;
}

void BM_StoreIngest(benchmark::State& state) {
    const ttg::Frame frame = make_frame(static_cast<std::size_t>(state.range(0)));
    ttg::TelemetryStore store;
    const ttg::bench::AllocSnapshot before = ttg::bench::alloc_snapshot();

    for (auto _ : state) {
        store.ingest(frame);
    }

    ttg::bench::report_allocations(state, before);
    state.SetItemsProcessed(static_cast<std::int64_t>(state.iterations()));
}
BENCHMARK(BM_StoreIngest)->Arg(1)->Arg(16)->Arg(128);

}
