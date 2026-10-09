#pragma once

#include <memory>
#include <string>

#include "ttg/telemetry_store.hpp"

namespace httplib {
class Server;
}

namespace ttg {

// Thin REST facade over the telemetry store. The server owns no state of its
// own; every request is served from the injected store.
class TelemetryHttpServer {
public:
    explicit TelemetryHttpServer(TelemetryStore& store);
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
    std::unique_ptr<httplib::Server> server_;
};

}  // namespace ttg
