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
    void stop();

private:
    TelemetryStore& store_;
    std::unique_ptr<httplib::Server> server_;
};

}  // namespace ttg
