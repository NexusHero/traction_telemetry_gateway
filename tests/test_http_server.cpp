// HTTP layer tests: the server in process, a real socket, a real client.
//
// The security headers are what the ZAP scan in supply-chain.yml checks from
// the outside. Asserting them here as well means a regression fails ctest on
// every platform in seconds, instead of only surfacing in the container job.

#include "ttg/http_server.hpp"

#include <cstdint>
#include <string>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <httplib.h>

#include "frame_builder.hpp"
#include "ttg/frame.hpp"
#include "ttg/telemetry_store.hpp"

namespace {

class HttpServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        port_ = server_.bind("127.0.0.1", 0);
        ASSERT_GT(port_, 0);
        // The socket is already listening after bind(), so a request sent
        // before serve() gets going simply waits in the accept backlog.
        thread_ = std::thread([this] { server_.serve(); });
    }

    void TearDown() override {
        server_.stop();
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    httplib::Client client() const {
        return httplib::Client("127.0.0.1", port_);
    }

    ttg::TelemetryStore store_{64};
    ttg::TelemetryHttpServer server_{store_};
    int port_{-1};
    std::thread thread_;
};

void expect_security_headers(const httplib::Result& res) {
    ASSERT_TRUE(res);
    EXPECT_EQ(res->get_header_value("Cache-Control"), "no-store");
    EXPECT_EQ(res->get_header_value("Content-Security-Policy"),
              "default-src 'none'; frame-ancestors 'none'");
    EXPECT_EQ(res->get_header_value("Cross-Origin-Resource-Policy"), "same-origin");
    EXPECT_EQ(res->get_header_value("X-Content-Type-Options"), "nosniff");
    EXPECT_EQ(res->get_header_value("X-Frame-Options"), "DENY");
}

TEST_F(HttpServerTest, ReadEndpointsCarrySecurityHeaders) {
    auto cli = client();
    for (const char* path : {"/v1/telemetry", "/v1/stats", "/healthz", "/readyz"}) {
        SCOPED_TRACE(path);
        const auto res = cli.Get(path);
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 200);
        expect_security_headers(res);
    }
}

TEST_F(HttpServerTest, AcceptedFrameCarriesSecurityHeaders) {
    ttg::ChannelValue channel;
    channel.id = 7;
    channel.as_int = 42;
    const std::vector<std::uint8_t> frame =
        ttg::test::build_frame(ttg::MsgType::Telemetry, 1, 1000, {channel});
    const std::string body(frame.begin(), frame.end());

    const auto res = client().Post("/v1/frames", body, "application/octet-stream");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 202);
    expect_security_headers(res);
}

// The error paths matter most: they are what a scanner (or an attacker) sees
// first, and they are produced by different code than the happy path.
TEST_F(HttpServerTest, RejectedFrameCarriesSecurityHeaders) {
    const auto res = client().Post("/v1/frames", "not a frame", "application/octet-stream");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 400);
    expect_security_headers(res);
}

TEST_F(HttpServerTest, UnknownPathCarriesSecurityHeaders) {
    const auto res = client().Get("/does-not-exist");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 404);
    EXPECT_EQ(res->get_header_value("Content-Type"), "application/json");
    expect_security_headers(res);
}

TEST_F(HttpServerTest, OversizedBodyIsRefusedBeforeTheParser) {
    const std::string body(ttg::kHeaderSize + ttg::kMaxPayloadLen + ttg::kCrcSize + 2, 'x');
    const auto res = client().Post("/v1/frames", body, "application/octet-stream");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 413);
    expect_security_headers(res);
    EXPECT_EQ(store_.stats().frames_rejected, 0U);
}

}  // namespace
