#pragma once

#include <cstdint>
#include <mutex>
#include <unordered_map>
#include <vector>

#include "ttg/frame.hpp"

namespace ttg {

struct ChannelSnapshot {
    std::uint16_t id{};
    ValueType type{ValueType::Int32};
    std::int32_t as_int{};
    float as_float{};
    std::uint64_t updated_at_ms{};
    std::uint64_t update_count{};
};

struct StoreStats {
    std::uint64_t frames_received{};
    std::uint64_t frames_rejected{};
    std::uint64_t channels_tracked{};
    // Ingest requests refused for a missing or wrong credential. Counted apart
    // from frames_rejected: those are malformed input from an authorised
    // producer, these are someone who is not one.
    std::uint64_t auth_failures{};
};

// Bounded in-memory store for the most recent value of each channel. Channel
// ids are attacker-controllable, so the map size is capped and inserts beyond
// the cap are rejected rather than allowed to grow without bound (FR 7 of
// IEC 62443-4-2, resource availability).
class TelemetryStore {
public:
    explicit TelemetryStore(std::size_t max_channels = 4096);

    void ingest(const Frame& frame);
    void record_rejected();
    void record_auth_failure();

    [[nodiscard]] std::vector<ChannelSnapshot> snapshot() const;
    [[nodiscard]] StoreStats stats() const;
    [[nodiscard]] std::size_t capacity() const noexcept { return max_channels_; }

private:
    const std::size_t max_channels_;
    mutable std::mutex mutex_;
    std::unordered_map<std::uint16_t, ChannelSnapshot> channels_;
    StoreStats stats_{};
};

}  // namespace ttg
