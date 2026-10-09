#include "ttg/http_server.hpp"

#include <algorithm>
#include <array>
#include <cstdint>
#include <span>
#include <string_view>

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

struct Route {
    std::string_view path;
    std::string_view allow;  // value of the Allow header, also the method whitelist
};

// Keep in sync with the handlers registered below and with docs/openapi.yaml.
// HEAD is listed because httplib answers it with the GET handler.
constexpr std::array<Route, 5> kRoutes{{
    {"/v1/frames", "POST"},
    {"/v1/telemetry", "GET, HEAD"},
    {"/v1/stats", "GET, HEAD"},
    {"/healthz", "GET, HEAD"},
    {"/readyz", "GET, HEAD"},
}};

// A syntactically valid method token (RFC 9110, 9.1; restricted here to
// upper-case letters, which every registered method uses) on an HTTP/1.x
// request that httplib does not know. Anything else that ends up as a 400 is
// a genuinely malformed request and stays a 400.
bool is_unrecognised_method(const httplib::Request& req) {
    const std::string& m = req.method;
    // httplib's own method set (Server::builtin_methods is private).
    constexpr std::array<std::string_view, 10> kKnown{
        "GET", "HEAD", "POST", "PUT", "DELETE", "CONNECT", "OPTIONS", "TRACE", "PATCH", "PRI"};
    if (m.empty() || std::find(kKnown.begin(), kKnown.end(), m) != kKnown.end()) {
        return false;
    }
    for (const char c : m) {
        if (c < 'A' || c > 'Z') {
            return false;
        }
    }
    return req.version == "HTTP/1.1" || req.version == "HTTP/1.0";
}

bool method_allowed(std::string_view allow, std::string_view method) {
    while (!allow.empty()) {
        const auto comma = allow.find(',');
        if (allow.substr(0, comma) == method) {
            return true;
        }
        if (comma == std::string_view::npos) {
            break;
        }
        allow.remove_prefix(comma + 2);  // ", "
    }
    return false;
}

}  // namespace

TelemetryHttpServer::TelemetryHttpServer(TelemetryStore& store)
    : store_(store), server_(std::make_unique<httplib::Server>()) {
    // Bound the request body before it reaches the parser. The parser would
    // also reject oversized frames, but refusing early is cheaper.
    server_->set_payload_max_length(kHeaderSize + kMaxPayloadLen + kCrcSize + 1);

    // The API-relevant subset of the OWASP REST Security Cheat Sheet headers,
    // plus CORP, which stops a browser page on another origin from embedding
    // responses (ZAP rule 90004).
    // Every response is JSON for a machine client, so nothing should be
    // cached, sniffed into another type, framed or allowed to load content.
    // Default headers are copied into the response before the request line is
    // even parsed, so 400s for malformed requests and 404s carry them too.
    // HSTS is absent on purpose: TLS terminates in front of the process (see
    // docs/threat-model.md), and HSTS over plain HTTP is ignored by clients.
    server_->set_default_headers({
        {"Cache-Control", "no-store"},
        {"Content-Security-Policy", "default-src 'none'; frame-ancestors 'none'"},
        {"Cross-Origin-Resource-Policy", "same-origin"},
        {"X-Content-Type-Options", "nosniff"},
        {"X-Frame-Options", "DENY"},
    });

    // A wrong method on a known path is 405 with an Allow header (RFC 9110,
    // 15.5.6). httplib would answer 404, claiming the resource does not exist,
    // or 400 for methods it has no handler table for (TRACE, CONNECT). Runs
    // before method dispatch, so it covers every method uniformly.
    server_->set_pre_routing_handler([](const httplib::Request& req, httplib::Response& res) {
        for (const Route& route : kRoutes) {
            if (req.path != route.path) {
                continue;
            }
            if (method_allowed(route.allow, req.method)) {
                return httplib::Server::HandlerResponse::Unhandled;
            }
            res.status = 405;
            res.set_header("Allow", std::string(route.allow));
            res.set_content(nlohmann::json{{"error", "method_not_allowed"}}.dump(),
                            "application/json");
            return httplib::Server::HandlerResponse::Handled;
        }
        return httplib::Server::HandlerResponse::Unhandled;
    });

    // QUERY (the IETF httpbis safe-method-with-body) is a standard method, so
    // the server recognises it - otherwise httplib refuses it while parsing
    // and it would be a 501 below. No route supports it: known paths get 405
    // from the pre-routing handler above, everything else the usual 404.
    server_->CustomRoute("QUERY", R"(.*)",
                         [](const httplib::Request&, httplib::Response& res) { res.status = 404; });

    server_->Post("/v1/frames", [this](const httplib::Request& req, httplib::Response& res) {
        const auto* bytes = reinterpret_cast<const std::uint8_t*>(req.body.data());
        const ParseResult result =
            parse_frame(std::span<const std::uint8_t>(bytes, req.body.size()));
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

    server_->set_error_handler([](const httplib::Request& req, httplib::Response& res) {
        // httplib rejects a method it has no handler table for while parsing
        // the request line, before any route runs, and reports 400. A
        // well-formed request with a method this server does not recognise is
        // 501 (RFC 9110, 15.6.2) - the client did nothing malformed.
        if (res.status == 400 && is_unrecognised_method(req)) {
            res.status = 501;
            res.set_content(nlohmann::json{{"error", "not_implemented"}}.dump(),
                            "application/json");
            return;
        }
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

int TelemetryHttpServer::bind(const std::string& host, int port) {
    if (port == 0) {
        return server_->bind_to_any_port(host);
    }
    return server_->bind_to_port(host, port) ? port : -1;
}

bool TelemetryHttpServer::serve() { return server_->listen_after_bind(); }

void TelemetryHttpServer::stop() {
    if (server_) {
        server_->stop();
    }
}

}  // namespace ttg
