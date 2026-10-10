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

ttg::Frame frame_for(unsigned writer, std::uint64_t iteration) {
    ttg::Frame frame;
    frame.timestamp_ms = 1'000 + iteration;
    for (std::uint16_t offset = 0; offset < kChannelsPerFrame; ++offset) {
        const auto id = static_cast<std::uint16_t>(writer * kChannelsPerFrame + offset);
        frame.channels.push_back(int_channel(id, static_cast<std::int32_t>(iteration)));
    }
    return frame;
}

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
    ttg::TelemetryStore store(4096);
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
    ttg::TelemetryStore store(4096);
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

    EXPECT_EQ(store.stats().frames_rejected, kTotalFrames);
}

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

}
