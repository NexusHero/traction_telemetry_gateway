#include <csignal>
#include <cstddef>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <optional>
#include <sstream>
#include <string>
#include <string_view>

#include "ttg/http_server.hpp"
#include "ttg/security_log.hpp"
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

// Shortest ingest token accepted: 32 characters, e.g. `openssl rand -hex 16`
// or more. A short shared secret is guessable over the network no matter how
// it is compared.
constexpr std::size_t kMinTokenLength = 32;

// The ingest token, preferably from a file (a Docker or Kubernetes secret
// mounted read-only), otherwise from the environment. A file keeps the secret
// out of `docker inspect`, /proc/<pid>/environ and crash reports.
// std::nullopt: a configured source could not be read - a startup error, never
// a silent fallback to "no token".
std::optional<std::string> load_ingest_token() {
    const std::string path = env_or("TTG_INGEST_TOKEN_FILE", "");
    if (!path.empty()) {
        std::ifstream in(path);
        if (!in) {
            std::cerr << "cannot read TTG_INGEST_TOKEN_FILE '" << path << "'\n";
            return std::nullopt;
        }
        std::stringstream content;
        content << in.rdbuf();
        std::string token = content.str();
        while (!token.empty() && (token.back() == '\n' || token.back() == '\r' ||
                                  token.back() == ' ' || token.back() == '\t')) {
            token.pop_back();
        }
        return token;
    }
    return env_or("TTG_INGEST_TOKEN", "");
}

}  // namespace

int main() {
    const std::string host = env_or("TTG_HOST", "0.0.0.0");
    const int port = env_int("TTG_PORT", 8080);
    const std::size_t max_channels = static_cast<std::size_t>(env_int("TTG_MAX_CHANNELS", 4096));

    // Security event log on stderr, one JSON object per line. On by default;
    // TTG_SECURITY_LOG=off is the opt-out CRA Annex I (2)(l) asks for.
    ttg::SecurityLog::Sink sink;
    if (env_or("TTG_SECURITY_LOG", "on") != "off") {
        sink = [](std::string_view line) { std::cerr << line << '\n'; };
    }
    ttg::SecurityLog security_log(sink);  // an empty sink is a disabled log

    // Secure by default (CRA Annex I (2)(b)): no token, no start. Running
    // without authentication is possible, but only as an explicit, logged
    // decision by the operator - never as the result of a missing variable.
    const std::optional<std::string> token = load_ingest_token();
    if (!token) {
        return EXIT_FAILURE;
    }
    ttg::HttpServerConfig config;
    config.security_log = &security_log;
    if (token->empty()) {
        if (env_or("TTG_ALLOW_UNAUTHENTICATED_INGEST", "") != "1") {
            std::cerr << "no ingest token configured: set TTG_INGEST_TOKEN_FILE (preferred) or "
                         "TTG_INGEST_TOKEN, or TTG_ALLOW_UNAUTHENTICATED_INGEST=1 to run "
                         "without authentication (not for production)\n";
            return EXIT_FAILURE;
        }
        security_log.record("config", "", "ingest_authentication_disabled");
    } else if (token->size() < kMinTokenLength) {
        std::cerr << "ingest token too short: " << token->size() << " characters, need at least "
                  << kMinTokenLength << '\n';
        return EXIT_FAILURE;
    } else {
        config.ingest_token = *token;
        security_log.record("config", "", "ingest_authentication_required");
    }

    ttg::TelemetryStore store(max_channels);
    ttg::TelemetryHttpServer server(store, config);
    g_server = &server;

    // Without these handlers SIGTERM kills the process mid-request instead of
    // letting the server drain, so failing to install them is a startup error.
    if (std::signal(SIGINT, handle_signal) == SIG_ERR ||
        std::signal(SIGTERM, handle_signal) == SIG_ERR) {
        std::cerr << "failed to install signal handlers\n";
        return EXIT_FAILURE;
    }

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
