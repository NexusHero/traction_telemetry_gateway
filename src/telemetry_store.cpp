#include "ttg/telemetry_store.hpp"

#include <algorithm>

namespace ttg {

TelemetryStore::TelemetryStore(std::size_t max_channels) : max_channels_(max_channels) {}

void TelemetryStore::ingest(const Frame& frame) {
    std::lock_guard<std::mutex> lock(mutex_);
    ++stats_.frames_received;
    for (const ChannelValue& value : frame.channels) {
        auto it = channels_.find(value.id);
        if (it == channels_.end()) {
            if (channels_.size() >= max_channels_) {
                continue;
            }
            ChannelSnapshot snap;
            snap.id = value.id;
            snap.type = value.type;
            snap.as_int = value.as_int;
            snap.as_float = value.as_float;
            snap.updated_at_ms = frame.timestamp_ms;
            snap.update_count = 1;
            channels_.emplace(value.id, snap);
            continue;
        }
        it->second.type = value.type;
        it->second.as_int = value.as_int;
        it->second.as_float = value.as_float;
        it->second.updated_at_ms = frame.timestamp_ms;
        ++it->second.update_count;
    }
    stats_.channels_tracked = channels_.size();
}

void TelemetryStore::record_auth_failure() {
    const std::lock_guard<std::mutex> lock(mutex_);
    ++stats_.auth_failures;
}

void TelemetryStore::record_rejected() {
    std::lock_guard<std::mutex> lock(mutex_);
    ++stats_.frames_rejected;
}

std::vector<ChannelSnapshot> TelemetryStore::snapshot() const {
    std::lock_guard<std::mutex> lock(mutex_);
    std::vector<ChannelSnapshot> out;
    out.reserve(channels_.size());
    for (const auto& [id, snap] : channels_) {
        (void)id;
        out.push_back(snap);
    }
    std::sort(out.begin(), out.end(),
              [](const ChannelSnapshot& a, const ChannelSnapshot& b) { return a.id < b.id; });
    return out;
}

StoreStats TelemetryStore::stats() const {
    std::lock_guard<std::mutex> lock(mutex_);
    return stats_;
}

}
