#include "ttg/http_server.hpp"

#include <cstdint>
#include <span>

#include <httplib.h>
#include <nlohmann/json.hpp>

#include "ttg/frame.hpp"
#include "ttg/parser.hpp"
#include "ttg/report.hpp"

namespace ttg {
namespace {

nlohmann::json error_body(ParseStatus status) {
    return nlohmann::json{{"error", to_string(status)}};
}

}  // namespace

TelemetryHttpServer::TelemetryHttpServer(TelemetryStore& store)
    : store_(store), server_(std::make_unique<httplib::Server>()) {
    // Bound the request body before it reaches the parser. The parser would
    // also reject oversized frames, but refusing early is cheaper.
    server_->set_payload_max_length(kHeaderSize + kMaxPayloadLen + kCrcSize + 1);

    server_->Post("/v1/frames", [this](const httplib::Request& req, httplib::Response& res) {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(req.body.data());
        const ParseResult result = parse_frame(std::span<const std::uint8_t>(bytes, req.body.size()));
        if (!result.ok()) {
            store_.record_rejected();
            res.status = 400;
            res.set_content(error_body(result.status).dump(), "application/json");
            return;
        }
        store_.ingest(result.frame);
        res.status = 202;
        res.set_content(to_json(result.frame).dump(), "application/json");
    });

    server_->Get("/v1/telemetry", [this](const httplib::Request&, httplib::Response& res) {
        res.set_content(to_json(store_.snapshot()).dump(), "application/json");
    });

    server_->Get("/v1/stats", [this](const httplib::Request&, httplib::Response& res) {
        res.set_content(to_json(store_.stats()).dump(), "application/json");
    });

    server_->Get("/healthz", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"alive"})", "application/json");
    });

    server_->Get("/readyz", [](const httplib::Request&, httplib::Response& res) {
        res.set_content(R"({"status":"ready"})", "application/json");
    });

    server_->set_error_handler([](const httplib::Request&, httplib::Response& res) {
        if (res.body.empty()) {
            res.set_content(nlohmann::json{{"error", "http_error"}, {"status", res.status}}.dump(),
                            "application/json");
        }
    });
}

TelemetryHttpServer::~TelemetryHttpServer() { stop(); }

bool TelemetryHttpServer::listen(const std::string& host, int port) {
    return server_->listen(host, port);
}

void TelemetryHttpServer::stop() {
    if (server_) {
        server_->stop();
    }
}

}  // namespace ttg
