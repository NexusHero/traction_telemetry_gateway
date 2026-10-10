#pragma once

#include <atomic>
#include <cstdint>

#include <benchmark/benchmark.h>

namespace ttg::bench {

struct AllocCounters {
    std::atomic<std::int64_t> num_allocs{0};
    std::atomic<std::int64_t> total_allocated_bytes{0};
};

[[nodiscard]] AllocCounters& alloc_counters();

struct AllocSnapshot {
    std::int64_t num_allocs{0};
    std::int64_t total_allocated_bytes{0};
};

[[nodiscard]] inline AllocSnapshot alloc_snapshot() {
    auto& counters = alloc_counters();
    return AllocSnapshot{
        counters.num_allocs.load(std::memory_order_relaxed),
        counters.total_allocated_bytes.load(std::memory_order_relaxed),
    };
}

inline void report_allocations(benchmark::State& state, AllocSnapshot before) {
    const AllocSnapshot after = alloc_snapshot();
    state.counters["allocs"] =
        benchmark::Counter(static_cast<double>(after.num_allocs - before.num_allocs),
                           benchmark::Counter::kAvgIterations);
    state.counters["alloc_bytes"] = benchmark::Counter(
        static_cast<double>(after.total_allocated_bytes - before.total_allocated_bytes),
        benchmark::Counter::kAvgIterations);
}

}
