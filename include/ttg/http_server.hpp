#pragma once

#include <memory>
#include <string>

#include "ttg/security_log.hpp"
#include "ttg/telemetry_store.hpp"

namespace httplib {
class Server;
}

namespace ttg {

struct HttpServerConfig {
    // Shared secret a producer presents as "Authorization: Bearer <token>" on
    // POST /v1/frames. Empty means ingest is unauthenticated - which only
    // tests do directly; main.cpp refuses to start that way unless the
    // operator opts out explicitly (secure by default, CRA Annex I (2)(b)).
    std::string ingest_token;

    // Not owned; may be null. Receives auth failures and rejected frames.
    SecurityLog* security_log{nullptr};
};

// Thin REST facade over the telemetry store. The server owns no state of its
// own; every request is served from the injected store.
class TelemetryHttpServer {
public:
    explicit TelemetryHttpServer(TelemetryStore& store, HttpServerConfig config = {});
    ~TelemetryHttpServer();

    TelemetryHttpServer(const TelemetryHttpServer&) = delete;
    TelemetryHttpServer& operator=(const TelemetryHttpServer&) = delete;

    // Blocks until stop() is called or the socket fails to bind.
    bool listen(const std::string& host, int port);

    // listen() split in two, for tests: bind() with port 0 picks a free port
    // and returns it (-1 on failure), so a test never races another process
    // for a fixed one. serve() then blocks like listen().
    int bind(const std::string& host, int port);
    bool serve();

    void stop();

private:
    TelemetryStore& store_;
    HttpServerConfig config_;
    std::unique_ptr<httplib::Server> server_;
};

}  // namespace ttg
