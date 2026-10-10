#include "ttg/report.hpp"

namespace ttg {

nlohmann::json to_json(const ChannelValue& value) {
    if (value.type == ValueType::Float32) {
        return nlohmann::json{
            {"id", value.id}, {"type", to_string(value.type)}, {"value", value.as_float}};
    }
    return nlohmann::json{
        {"id", value.id}, {"type", to_string(value.type)}, {"value", value.as_int}};
}

nlohmann::json to_json(const Frame& frame) {
    nlohmann::json channels = nlohmann::json::array();
    for (const ChannelValue& value : frame.channels) {
        channels.push_back(to_json(value));
    }
    return nlohmann::json{
        {"msg_type", to_string(frame.msg_type)}, {"sequence", frame.sequence},
        {"timestamp_ms", frame.timestamp_ms},    {"channel_count", frame.channels.size()},
        {"channels", std::move(channels)},
    };
}

nlohmann::json to_json(const std::vector<ChannelSnapshot>& snapshot) {
    nlohmann::json channels = nlohmann::json::array();
    for (const ChannelSnapshot& snap : snapshot) {
        nlohmann::json entry{
            {"id", snap.id},
            {"type", to_string(snap.type)},
            {"updated_at_ms", snap.updated_at_ms},
            {"update_count", snap.update_count},
        };
        if (snap.type == ValueType::Float32) {
            entry["value"] = snap.as_float;
        } else {
            entry["value"] = snap.as_int;
        }
        channels.push_back(std::move(entry));
    }
    return nlohmann::json{{"channels", std::move(channels)}};
}

nlohmann::json to_json(const StoreStats& stats) {
    return nlohmann::json{
        {"frames_received", stats.frames_received},
        {"frames_rejected", stats.frames_rejected},
        {"channels_tracked", stats.channels_tracked},
        {"auth_failures", stats.auth_failures},
    };
}

}  // namespace ttg
