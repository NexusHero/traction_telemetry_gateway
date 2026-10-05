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

// Builds a parsed frame with `channels` distinct channels. Built once, outside
// the timed region.
ttg::Frame make_frame(std::size_t channels) {
    std::vector<ChannelValue> values;
    values.reserve(channels);
    for (std::uint16_t i = 0; i < channels; ++i) {
        values.push_back(make_int(i, static_cast<std::int32_t>(i)));
    }
    const auto bytes = ttg::test::build_frame(MsgType::Telemetry, 1, 0, values);
    return ttg::parse_frame(bytes).frame;
}

// Ingest into a long-lived store: after the first iteration the channel slots
// already exist, so this measures the steady-state update path and shows that
// it allocates nothing.
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

}  // namespace
