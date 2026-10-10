#include "ttg/http_server.hpp"

#include <cstdint>
#include <mutex>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include <gtest/gtest.h>
#include <httplib.h>

#include "frame_builder.hpp"
#include "ttg/frame.hpp"
#include "ttg/security_log.hpp"
#include "ttg/telemetry_store.hpp"

namespace {

class HttpServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        port_ = server_.bind("127.0.0.1", 0);
        ASSERT_GT(port_, 0);
        thread_ = std::thread([this] { server_.serve(); });
    }

    void TearDown() override {
        server_.stop();
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    httplib::Client client() const { return httplib::Client("127.0.0.1", port_); }

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

TEST_F(HttpServerTest, WrongMethodOnKnownPathIs405WithAllow) {
    auto cli = client();

    const auto get_frames = cli.Get("/v1/frames");
    ASSERT_TRUE(get_frames);
    EXPECT_EQ(get_frames->status, 405);
    EXPECT_EQ(get_frames->get_header_value("Allow"), "POST");
    EXPECT_EQ(get_frames->body, R"({"error":"method_not_allowed"})");
    expect_security_headers(get_frames);

    const auto delete_stats = cli.Delete("/v1/stats");
    ASSERT_TRUE(delete_stats);
    EXPECT_EQ(delete_stats->status, 405);
    EXPECT_EQ(delete_stats->get_header_value("Allow"), "GET, HEAD");
}

TEST_F(HttpServerTest, TraceOnKnownPathIs405) {
    httplib::Request req;
    req.method = "TRACE";
    req.path = "/healthz";
    const auto res = client().send(req);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 405);
    EXPECT_EQ(res->get_header_value("Allow"), "GET, HEAD");
}

TEST_F(HttpServerTest, QueryMethodIsRecognisedButNotAllowed) {
    httplib::Request req;
    req.method = "QUERY";
    req.path = "/v1/telemetry";
    auto res = client().send(req);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 405);
    EXPECT_EQ(res->get_header_value("Allow"), "GET, HEAD");

    req.path = "/does-not-exist";
    res = client().send(req);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 404);
}

TEST_F(HttpServerTest, UnrecognisedMethodIs501) {
    httplib::Request req;
    req.method = "FROBNICATE";
    req.path = "/healthz";
    const auto res = client().send(req);
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 501);
    EXPECT_EQ(res->body, R"({"error":"not_implemented"})");
    expect_security_headers(res);
}

TEST_F(HttpServerTest, HeadIsAllowedWhereGetIs) {
    const auto res = client().Head("/v1/stats");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
}

TEST_F(HttpServerTest, WrongMethodOnUnknownPathStays404) {
    const auto res = client().Delete("/does-not-exist");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 404);
}

const std::string kToken(32, 't');

class AuthHttpServerTest : public ::testing::Test {
protected:
    void SetUp() override {
        port_ = server_.bind("127.0.0.1", 0);
        ASSERT_GT(port_, 0);
        thread_ = std::thread([this] { server_.serve(); });
    }

    void TearDown() override {
        server_.stop();
        if (thread_.joinable()) {
            thread_.join();
        }
    }

    static ttg::HttpServerConfig config(ttg::SecurityLog* log) {
        ttg::HttpServerConfig c;
        c.ingest_token = kToken;
        c.security_log = log;
        return c;
    }

    httplib::Client client() const { return httplib::Client("127.0.0.1", port_); }

    static std::string valid_frame() {
        ttg::ChannelValue channel;
        channel.id = 3;
        channel.as_int = 7;
        const auto bytes = ttg::test::build_frame(ttg::MsgType::Telemetry, 1, 1000, {channel});
        return {bytes.begin(), bytes.end()};
    }

    std::vector<std::string> logged() {
        const std::lock_guard<std::mutex> lock(lines_mutex_);
        return lines_;
    }

    std::mutex lines_mutex_;
    std::vector<std::string> lines_;
    ttg::SecurityLog log_{[this](std::string_view line) {
        const std::lock_guard<std::mutex> lock(lines_mutex_);
        lines_.emplace_back(line);
    }};
    ttg::TelemetryStore store_{64};
    ttg::TelemetryHttpServer server_{store_, config(&log_)};
    int port_{-1};
    std::thread thread_;
};

TEST_F(AuthHttpServerTest, MissingTokenIs401AndNeverReachesTheParser) {
    const auto res = client().Post("/v1/frames", valid_frame(), "application/octet-stream");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 401);
    EXPECT_EQ(res->get_header_value("WWW-Authenticate"), R"(Bearer realm="ttg-ingest")");
    EXPECT_EQ(res->body, R"({"error":"unauthorized"})");
    expect_security_headers(res);

    const auto stats = store_.stats();
    EXPECT_EQ(stats.auth_failures, 1U);
    EXPECT_EQ(stats.frames_received, 0U);
    EXPECT_EQ(stats.frames_rejected, 0U);
}

TEST_F(AuthHttpServerTest, WrongTokenIs401) {
    const httplib::Headers headers{{"Authorization", "Bearer not-the-token"}};
    const auto res =
        client().Post("/v1/frames", headers, valid_frame(), "application/octet-stream");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 401);
    EXPECT_EQ(store_.stats().auth_failures, 1U);
}

TEST_F(AuthHttpServerTest, TokenThatIsOnlyAPrefixIs401) {
    const std::string prefix = std::string(kToken).substr(0, 16);
    const httplib::Headers headers{{"Authorization", "Bearer " + prefix}};
    const auto res =
        client().Post("/v1/frames", headers, valid_frame(), "application/octet-stream");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 401);
}

TEST_F(AuthHttpServerTest, CorrectTokenIsAccepted) {
    for (const char* scheme : {"Bearer ", "bearer "}) {
        SCOPED_TRACE(scheme);
        const httplib::Headers headers{{"Authorization", std::string(scheme) + kToken}};
        const auto res =
            client().Post("/v1/frames", headers, valid_frame(), "application/octet-stream");
        ASSERT_TRUE(res);
        EXPECT_EQ(res->status, 202);
    }
    EXPECT_EQ(store_.stats().auth_failures, 0U);
    EXPECT_EQ(store_.stats().frames_received, 2U);
}

TEST_F(AuthHttpServerTest, ReadEndpointsStayOpen) {
    const auto res = client().Get("/v1/stats");
    ASSERT_TRUE(res);
    EXPECT_EQ(res->status, 200);
}

TEST_F(AuthHttpServerTest, SecurityEventsAreLogged) {
    auto cli = client();
    ASSERT_TRUE(cli.Post("/v1/frames", valid_frame(), "application/octet-stream"));
    const httplib::Headers headers{{"Authorization", std::string("Bearer ") + kToken}};
    ASSERT_TRUE(cli.Post("/v1/frames", headers, "not a frame", "application/octet-stream"));

    const auto lines = logged();
    ASSERT_EQ(lines.size(), 2U);
    EXPECT_NE(lines[0].find(R"("event":"auth_failure")"), std::string::npos);
    EXPECT_NE(lines[0].find(R"("detail":"missing_token")"), std::string::npos);
    EXPECT_NE(lines[1].find(R"("event":"frame_rejected")"), std::string::npos);
    EXPECT_NE(lines[1].find(R"("detail":"too_short")"), std::string::npos);
}

}
