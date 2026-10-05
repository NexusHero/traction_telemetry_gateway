#pragma once

#include <atomic>
#include <cstdint>

#include <benchmark/benchmark.h>

namespace ttg::bench {

// Process-wide allocation counters, driven from the overridden global
// operator new / delete in memory_manager.cpp. The counters are kept out of
// the hot path: two relaxed atomic adds per allocation.
struct AllocCounters {
    std::atomic<std::int64_t> num_allocs{0};
    std::atomic<std::int64_t> total_allocated_bytes{0};
};

[[nodiscard]] AllocCounters& alloc_counters();

struct AllocSnapshot {
    std::int64_t num_allocs{0};
    std::int64_t total_allocated_bytes{0};
};

// Snapshot the counters right before the timed loop.
[[nodiscard]] inline AllocSnapshot alloc_snapshot() {
    auto& counters = alloc_counters();
    return AllocSnapshot{
        counters.num_allocs.load(std::memory_order_relaxed),
        counters.total_allocated_bytes.load(std::memory_order_relaxed),
    };
}

// Call once after the timed loop to report the allocations the loop caused,
// averaged per iteration. The result shows up in the console "counters" column
// and in the JSON output.
inline void report_allocations(benchmark::State& state, AllocSnapshot before) {
    const AllocSnapshot after = alloc_snapshot();
    state.counters["allocs"] = benchmark::Counter(
        static_cast<double>(after.num_allocs - before.num_allocs),
        benchmark::Counter::kAvgIterations);
    state.counters["alloc_bytes"] = benchmark::Counter(
        static_cast<double>(after.total_allocated_bytes - before.total_allocated_bytes),
        benchmark::Counter::kAvgIterations);
}

}  // namespace ttg::bench
