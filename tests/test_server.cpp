#include "harness.hpp"

#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include "debug_harness/harness.hpp"
#include "debug_harness/server.hpp"

#include <atomic>
#include <string>
#include <thread>

namespace {

    struct server_guard {
        ~server_guard() { debug_harness::stop(); }
    };

    struct route_guard {
        std::string path;
        ~route_guard() { debug_harness::unregister_route(path); }
    };

    // Pumps on_frame on its own thread, standing in for the host's render loop.
    class frame_pumper {
    public:
        frame_pumper()
            : thread_([this] {
                  thread_id_.store(GetCurrentThreadId());
                  while (!stop_.load()) {
                      debug_harness::on_frame();
                      std::this_thread::sleep_for(std::chrono::milliseconds(1));
                  }
              }) {}
        ~frame_pumper() {
            stop_.store(true);
            thread_.join();
        }
        DWORD thread_id() const {
            while (thread_id_.load() == 0)
                std::this_thread::yield();
            return thread_id_.load();
        }

    private:
        std::atomic<bool> stop_{false};
        std::atomic<DWORD> thread_id_{0};
        std::thread thread_;
    };

    // One blocking HTTP/1.0 exchange with 127.0.0.1:port. Returns the raw response,
    // or "" on any socket failure.
    std::string http_exchange(unsigned short port, const std::string& request_text) {
        WSADATA data = {};
        if (WSAStartup(MAKEWORD(2, 2), &data) != 0) return "";

        std::string response;
        const SOCKET client = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (client != INVALID_SOCKET) {
            sockaddr_in address = {};
            address.sin_family = AF_INET;
            address.sin_port = htons(port);
            inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

            DWORD timeout_ms = 5000;
            setsockopt(client, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<const char*>(&timeout_ms), sizeof(timeout_ms));

            if (connect(client, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0) {
                send(client, request_text.data(), static_cast<int>(request_text.size()), 0);
                char buffer[4096];
                for (;;) {
                    const int received = recv(client, buffer, sizeof(buffer), 0);
                    if (received <= 0) break;
                    response.append(buffer, static_cast<size_t>(received));
                }
            }
            closesocket(client);
        }
        WSACleanup();
        return response;
    }

    std::string http_get(unsigned short port, const std::string& target) {
        return http_exchange(port, "GET " + target + " HTTP/1.0\r\nHost: 127.0.0.1\r\n\r\n");
    }

    bool contains(const std::string& haystack, const std::string& needle) {
        return haystack.find(needle) != std::string::npos;
    }
}

TEST(server_serves_ping_over_loopback) {
    server_guard guard;
    debug_harness::configure({});

    std::string error;
    CHECK(debug_harness::start(0, error));
    CHECK_STR_EQ(error, "");
    CHECK(debug_harness::running());
    const unsigned short port = debug_harness::port();
    CHECK(port != 0);

    const auto response = http_get(port, "/ping");
    CHECK(contains(response, "HTTP/1.0 200"));
    CHECK(contains(response, "\"ok\":true"));
    CHECK(contains(response, "\"port\":" + std::to_string(port)));

    const auto missing = http_get(port, "/nope");
    CHECK(contains(missing, "HTTP/1.0 404"));

    // Stats are recorded after the response is sent, so give the server a moment.
    for (int i = 0; i < 200 && debug_harness::get_stats().request_count < 2; ++i)
        std::this_thread::sleep_for(std::chrono::milliseconds(5));
    const auto stats = debug_harness::get_stats();
    CHECK_EQ(stats.request_count, static_cast<uint64_t>(2));
    CHECK_STR_EQ(stats.last_request, "GET /nope");
    CHECK(stats.started_tick_ms != 0);

    debug_harness::stop();
    CHECK(!debug_harness::running());
    CHECK_EQ(debug_harness::port(), static_cast<unsigned short>(0));
    CHECK(http_get(port, "/ping").empty());
}

TEST(server_start_twice_is_refused) {
    server_guard guard;
    std::string error;
    CHECK(debug_harness::start(0, error));
    CHECK(!debug_harness::start(0, error));
    CHECK_STR_EQ(error, "already running");
    debug_harness::stop();
    debug_harness::stop(); // idempotent
    CHECK(debug_harness::start(0, error)); // and restartable
}

TEST(server_bind_failure_reports_an_error) {
    server_guard guard;
    std::string error;
    CHECK(debug_harness::start(0, error));
    const unsigned short taken = debug_harness::port();
    debug_harness::stop();

    // Occupy the port ourselves, then ask the harness for it.
    WSADATA data = {};
    CHECK(WSAStartup(MAKEWORD(2, 2), &data) == 0);
    const SOCKET blocker = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    sockaddr_in address = {};
    address.sin_family = AF_INET;
    address.sin_port = htons(taken);
    inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);
    const bool bound = bind(blocker, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == 0 &&
                       listen(blocker, 1) == 0;

    const bool started = bound && debug_harness::start(taken, error);
    closesocket(blocker);
    WSACleanup();

    CHECK(bound);
    CHECK(!started);
    CHECK(error.find("bind to 127.0.0.1:") == 0);
    CHECK(!debug_harness::running());
    CHECK_STR_EQ(debug_harness::get_stats().last_error, error);
}

TEST(server_run_on_game_thread_runs_on_the_pumping_thread) {
    frame_pumper pumper;
    DWORD ran_on = 0;
    CHECK(debug_harness::run_on_game_thread([&] { ran_on = GetCurrentThreadId(); }));
    CHECK_EQ(ran_on, pumper.thread_id());

    // A throwing job still completes, and does not take the pumping thread down.
    CHECK(debug_harness::run_on_game_thread([] { throw 1; }));
    bool after = false;
    CHECK(debug_harness::run_on_game_thread([&] { after = true; }));
    CHECK(after);
}

TEST(server_run_on_game_thread_nested_call_runs_inline) {
    frame_pumper pumper;
    bool inner_ran = false;
    bool inner_result = false;
    CHECK(debug_harness::run_on_game_thread(
        [&] { inner_result = debug_harness::run_on_game_thread([&] { inner_ran = true; }, 100); }));
    CHECK(inner_result);
    CHECK(inner_ran);
}

TEST(server_run_on_game_thread_times_out_and_withdraws_the_job) {
    // Nobody is pumping, so the job is never picked up.
    bool ran = false;
    CHECK(!debug_harness::run_on_game_thread([&] { ran = true; }, 50));

    // A later frame must not run the withdrawn job (it may capture dead locals).
    debug_harness::on_frame();
    CHECK(!ran);
}

TEST(server_registered_route_can_marshal_to_the_game_thread) {
    server_guard guard;
    route_guard route{"/test.game"};
    debug_harness::register_route(route.path, [](const debug_harness::http::request&, int& out_status) {
        DWORD id = 0;
        if (!debug_harness::run_on_game_thread([&] { id = GetCurrentThreadId(); }, 2000)) {
            out_status = 504;
            return std::string("{\"ok\":false}");
        }
        return "{\"ok\":true,\"thread\":" + std::to_string(id) + "}";
    });

    std::string error;
    CHECK(debug_harness::start(0, error));

    {
        frame_pumper pumper;
        const auto response = http_get(debug_harness::port(), "/test.game");
        CHECK(contains(response, "HTTP/1.0 200"));
        CHECK(contains(response, "\"thread\":" + std::to_string(pumper.thread_id())));
    }
}
