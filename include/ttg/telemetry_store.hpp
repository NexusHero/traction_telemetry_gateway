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
    std::uint64_t auth_failures{};
};

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

}
