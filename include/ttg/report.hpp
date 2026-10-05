#pragma once

#include <string>
#include <vector>

#include <nlohmann/json.hpp>

#include "ttg/frame.hpp"
#include "ttg/telemetry_store.hpp"

namespace ttg {

[[nodiscard]] nlohmann::json to_json(const ChannelValue& value);
[[nodiscard]] nlohmann::json to_json(const Frame& frame);
[[nodiscard]] nlohmann::json to_json(const std::vector<ChannelSnapshot>& snapshot);
[[nodiscard]] nlohmann::json to_json(const StoreStats& stats);

}  // namespace ttg
