#include "memory_manager.hpp"

#include <cstdlib>
#include <new>

namespace ttg::bench {

AllocCounters& alloc_counters() {
    static AllocCounters counters;
    return counters;
}

}  // namespace ttg::bench

// ---------------------------------------------------------------------------
// Global operator new/delete overrides. They count every heap allocation in
// the process while the benchmark runs. The overrides must live in this TU so
// they are defined exactly once.
// ---------------------------------------------------------------------------

namespace {
void count(std::size_t size) {
    auto& counters = ttg::bench::alloc_counters();
    counters.num_allocs.fetch_add(1, std::memory_order_relaxed);
    counters.total_allocated_bytes.fetch_add(static_cast<std::int64_t>(size),
                                             std::memory_order_relaxed);
}
}  // namespace

void* operator new(std::size_t size) {
    count(size);
    if (void* p = std::malloc(size)) {
        return p;
    }
    throw std::bad_alloc();
}

void* operator new(std::size_t size, std::align_val_t alignment) {
    count(size);
    void* p = nullptr;
    if (::posix_memalign(&p, static_cast<std::size_t>(alignment), size) != 0) {
        throw std::bad_alloc();
    }
    return p;
}

void operator delete(void* p) noexcept { std::free(p); }
void operator delete(void* p, std::size_t) noexcept { std::free(p); }
void operator delete(void* p, std::align_val_t) noexcept { std::free(p); }
void operator delete(void* p, std::size_t, std::align_val_t) noexcept { std::free(p); }

void* operator new[](std::size_t size) { return ::operator new(size); }
void* operator new[](std::size_t size, std::align_val_t alignment) {
    return ::operator new(size, alignment);
}

void operator delete[](void* p) noexcept { ::operator delete(p); }
void operator delete[](void* p, std::size_t size) noexcept { ::operator delete(p, size); }
void operator delete[](void* p, std::align_val_t alignment) noexcept {
    ::operator delete(p, alignment);
}
void operator delete[](void* p, std::size_t size, std::align_val_t alignment) noexcept {
    ::operator delete(p, size, alignment);
}
