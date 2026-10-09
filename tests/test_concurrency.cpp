// Concurrency tests for TelemetryStore.
//
// These exist for ThreadSanitizer. The server hands every request to a thread
// from the httplib pool, so TelemetryStore is touched concurrently by design -
// but the rest of the suite is single-threaded, which means a TSan build of it
// would pass without ever exercising a single lock. A race that no test can
// trigger is a race no sanitizer can see.
//
// The assertions below are deliberately about *invariants that survive any
// interleaving*, not about a specific outcome: with N threads racing, the only
// honest statements are totals, bounds and internal consistency. The real
// verdict comes from TSan's report (or absence of one) when this runs under
// -DTTG_SANITIZER=thread.

#include "ttg/telemetry_store.hpp"

#include <atomic>
#include <cstdint>
#include <thread>
#include <vector>

#include <gtest/gtest.h>

#include "ttg/frame.hpp"

namespace {

constexpr unsigned kWriterThreads = 4;
constexpr unsigned kReaderThreads = 2;
constexpr std::uint64_t kFramesPerWriter = 2000;
constexpr std::uint16_t kChannelsPerFrame = 8;

// Derived totals, pre-typed. The store reports std::uint64_t counters and
// std::uint16_t channel ids; comparing those against a plain `unsigned`
// product trips -Wsign-compare, which this project builds with.
constexpr std::uint64_t kTotalFrames = kWriterThreads * kFramesPerWriter;
constexpr std::uint16_t kChannelIdLimit =
    static_cast<std::uint16_t>(kWriterThreads * kChannelsPerFrame);
constexpr std::uint64_t kTotalChannels = kChannelIdLimit;

ttg::ChannelValue int_channel(std::uint16_t id, std::int32_t value) {
    ttg::ChannelValue channel;
    channel.id = id;
    channel.type = ttg::ValueType::Int32;
    channel.as_int = value;
    return channel;
}

// Each writer owns a disjoint slice of the channel id space, so a channel's
// update_count is attributable to exactly one thread. That turns "no crash"
// into a checkable claim: no update may be lost.
ttg::Frame frame_for(unsigned writer, std::uint64_t iteration) {
    ttg::Frame frame;
    frame.timestamp_ms = 1'000 + iteration;
    for (std::uint16_t offset = 0; offset < kChannelsPerFrame; ++offset) {
        const auto id = static_cast<std::uint16_t>(writer * kChannelsPerFrame + offset);
        frame.channels.push_back(int_channel(id, static_cast<std::int32_t>(iteration)));
    }
    return frame;
}

// A barrier so the threads actually overlap. Without one, a short workload can
// finish on thread 0 before thread 3 has started, and the test silently
// degenerates into the sequential case it was written to avoid.
class SpinBarrier {
public:
    explicit SpinBarrier(unsigned expected) : expected_(expected) {}

    void arrive_and_wait() {
        ++arrived_;
        while (arrived_.load(std::memory_order_acquire) < expected_) {
            std::this_thread::yield();
        }
    }

private:
    const unsigned expected_;
    std::atomic<unsigned> arrived_{0};
};

TEST(TelemetryStoreConcurrency, ConcurrentIngestLosesNoUpdate) {
    ttg::TelemetryStore store(/*max_channels=*/4096);
    SpinBarrier barrier(kWriterThreads);

    std::vector<std::thread> writers;
    writers.reserve(kWriterThreads);
    for (unsigned writer = 0; writer < kWriterThreads; ++writer) {
        writers.emplace_back([&store, &barrier, writer] {
            barrier.arrive_and_wait();
            for (std::uint64_t i = 0; i < kFramesPerWriter; ++i) {
                store.ingest(frame_for(writer, i));
            }
        });
    }
    for (std::thread& writer : writers) {
        writer.join();
    }

    const auto stats = store.stats();
    EXPECT_EQ(stats.frames_received, kTotalFrames);
    EXPECT_EQ(stats.frames_rejected, 0U);
    EXPECT_EQ(stats.channels_tracked, kTotalChannels);

    // Every channel was written by exactly one thread, kFramesPerWriter times.
    // A lost update under a dropped lock shows up here as a low count.
    const auto snapshot = store.snapshot();
    ASSERT_EQ(snapshot.size(), kTotalChannels);
    for (const ttg::ChannelSnapshot& channel : snapshot) {
        EXPECT_EQ(channel.update_count, kFramesPerWriter)
            << "channel " << channel.id << " lost updates";
        EXPECT_EQ(channel.as_int, static_cast<std::int32_t>(kFramesPerWriter - 1))
            << "channel " << channel.id << " does not hold the last value written";
    }
}

TEST(TelemetryStoreConcurrency, SnapshotIsConsistentDuringWrites) {
    ttg::TelemetryStore store(/*max_channels=*/4096);
    std::atomic<bool> stop{false};
    SpinBarrier barrier(kWriterThreads + kReaderThreads);

    std::vector<std::thread> threads;
    threads.reserve(kWriterThreads + kReaderThreads);

    for (unsigned writer = 0; writer < kWriterThreads; ++writer) {
        threads.emplace_back([&store, &barrier, writer] {
            barrier.arrive_and_wait();
            for (std::uint64_t i = 0; i < kFramesPerWriter; ++i) {
                store.ingest(frame_for(writer, i));
            }
        });
    }

    // Readers race the writers for the whole run. They cannot assert on values
    // - any snapshot is a valid point in time - but a snapshot must never be
    // torn: ids stay sorted and in range, and stats stay mutually consistent.
    std::atomic<std::uint64_t> reads{0};
    for (unsigned reader = 0; reader < kReaderThreads; ++reader) {
        threads.emplace_back([&store, &barrier, &stop, &reads] {
            barrier.arrive_and_wait();
            while (!stop.load(std::memory_order_relaxed)) {
                const auto snapshot = store.snapshot();
                const auto stats = store.stats();

                ASSERT_LE(snapshot.size(), store.capacity());
                ASSERT_LE(stats.channels_tracked, store.capacity());
                for (std::size_t i = 1; i < snapshot.size(); ++i) {
                    ASSERT_LT(snapshot[i - 1].id, snapshot[i].id)
                        << "snapshot is not sorted by id - torn read";
                }
                for (const ttg::ChannelSnapshot& channel : snapshot) {
                    ASSERT_GT(channel.update_count, 0U)
                        << "channel " << channel.id << " published before initialisation";
                    ASSERT_LT(channel.id, kChannelIdLimit);
                }
                reads.fetch_add(1, std::memory_order_relaxed);
            }
        });
    }

    for (unsigned writer = 0; writer < kWriterThreads; ++writer) {
        threads[writer].join();
    }
    stop.store(true, std::memory_order_relaxed);
    for (std::size_t i = kWriterThreads; i < threads.size(); ++i) {
        threads[i].join();
    }

    // If the readers never ran, the test proved nothing about concurrent access.
    EXPECT_GT(reads.load(), 0U) << "reader threads never observed the store";
    EXPECT_EQ(store.stats().frames_received, kTotalFrames);
}

TEST(TelemetryStoreConcurrency, RejectionCounterIsAtomicAcrossThreads) {
    ttg::TelemetryStore store;
    SpinBarrier barrier(kWriterThreads);

    std::vector<std::thread> threads;
    threads.reserve(kWriterThreads);
    for (unsigned thread_index = 0; thread_index < kWriterThreads; ++thread_index) {
        threads.emplace_back([&store, &barrier] {
            barrier.arrive_and_wait();
            for (std::uint64_t i = 0; i < kFramesPerWriter; ++i) {
                store.record_rejected();
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }

    // A plain ++ on an unguarded counter loses increments here almost every run;
    // this is the cheapest regression test for the store's locking.
    EXPECT_EQ(store.stats().frames_rejected, kTotalFrames);
}

// The cap is enforced under the same lock as the inserts it guards. With
// max_channels smaller than the id space the writers use, the store must land
// exactly on the cap - never above it, which would mean two threads both saw
// room for the last slot.
TEST(TelemetryStoreConcurrency, ChannelCapHoldsUnderContention) {
    constexpr std::size_t kCap = 16;
    ttg::TelemetryStore store(kCap);
    SpinBarrier barrier(kWriterThreads);

    std::vector<std::thread> threads;
    threads.reserve(kWriterThreads);
    for (unsigned writer = 0; writer < kWriterThreads; ++writer) {
        threads.emplace_back([&store, &barrier, writer] {
            barrier.arrive_and_wait();
            for (std::uint64_t i = 0; i < kFramesPerWriter; ++i) {
                store.ingest(frame_for(writer, i));
            }
        });
    }
    for (std::thread& thread : threads) {
        thread.join();
    }

    EXPECT_EQ(store.snapshot().size(), kCap);
    EXPECT_EQ(store.stats().channels_tracked, kCap);
    EXPECT_EQ(store.stats().frames_received, kTotalFrames);
}

}  // namespace
