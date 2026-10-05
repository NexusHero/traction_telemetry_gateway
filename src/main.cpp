#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <iostream>
#include <string>

#include "ttg/http_server.hpp"
#include "ttg/telemetry_store.hpp"

namespace {

ttg::TelemetryHttpServer* g_server = nullptr;

extern "C" void handle_signal(int) {
    if (g_server != nullptr) {
        g_server->stop();
    }
}

std::string env_or(const char* name, const std::string& fallback) {
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    return value;
}

int env_int(const char* name, int fallback) {
    const char* value = std::getenv(name);
    if (value == nullptr || *value == '\0') {
        return fallback;
    }
    try {
        return std::stoi(value);
    } catch (...) {
        return fallback;
    }
}

}  // namespace

int main() {
    const std::string host = env_or("TTG_HOST", "0.0.0.0");
    const int port = env_int("TTG_PORT", 8080);
    const std::size_t max_channels = static_cast<std::size_t>(env_int("TTG_MAX_CHANNELS", 4096));

    ttg::TelemetryStore store(max_channels);
    ttg::TelemetryHttpServer server(store);
    g_server = &server;

    std::signal(SIGINT, handle_signal);
    std::signal(SIGTERM, handle_signal);

    std::cout << "traction-telemetry-gateway listening on " << host << ':' << port
              << " (max_channels=" << max_channels << ")\n";

    const bool ok = server.listen(host, port);
    g_server = nullptr;
    if (!ok) {
        std::cerr << "failed to bind " << host << ':' << port << '\n';
        return EXIT_FAILURE;
    }
    return EXIT_SUCCESS;
}
