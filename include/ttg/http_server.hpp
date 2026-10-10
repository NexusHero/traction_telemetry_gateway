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
    std::string ingest_token;

    SecurityLog* security_log{nullptr};
};

class TelemetryHttpServer {
public:
    explicit TelemetryHttpServer(TelemetryStore& store, HttpServerConfig config = {});
    ~TelemetryHttpServer();

    TelemetryHttpServer(const TelemetryHttpServer&) = delete;
    TelemetryHttpServer& operator=(const TelemetryHttpServer&) = delete;

    bool listen(const std::string& host, int port);

    int bind(const std::string& host, int port);
    bool serve();

    void stop();

private:
    TelemetryStore& store_;
    HttpServerConfig config_;
    std::unique_ptr<httplib::Server> server_;
};

}
