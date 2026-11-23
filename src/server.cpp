#include "debug_harness/server.hpp"

// winsock2 before anything that pulls in <Windows.h> (mem.hpp via routes).
#include <WinSock2.h>
#include <WS2tcpip.h>
#include <Windows.h>

#include <atomic>
#include <chrono>
#include <condition_variable>
#include <memory>
#include <mutex>
#include <thread>
#include <vector>

#include "debug_harness/harness.hpp"
#include "debug_harness/http.hpp"
#include "debug_harness/routes.hpp"
#include "internal/game_thread.hpp"

namespace {

    constexpr size_t max_request_bytes = 64 * 1024;
    constexpr int accept_timeout_ms = 200; // how often the accept loop checks `stopping`

    // One posted job. Shared between the waiting caller and the queue, so neither side
    // can outlive the other's view of it.
    struct job_state {
        enum class phase { pending, running, done, cancelled };

        std::function<void()> work;
        std::mutex mutex;
        std::condition_variable changed;
        phase current = phase::pending;
    };

    struct server_state {
        std::mutex mutex; // serialises start/stop
        std::thread thread;
        std::atomic<bool> stopping{false};
        std::atomic<bool> running{false};
        SOCKET listener = INVALID_SOCKET;
        std::atomic<unsigned short> port{0};
        bool winsock_ready = false;

        debug_harness::server_stats stats;
        std::mutex stats_mutex;

        std::mutex job_mutex;
        std::vector<std::shared_ptr<job_state>> jobs;
    };

    server_state& state() {
        static server_state instance;
        return instance;
    }

    // True while this thread is inside pump_game_thread, so a job that itself calls
    // run_on_game_thread runs the nested job inline instead of deadlocking.
    thread_local bool in_pump = false;

    void record_error(const std::string& message) {
        auto& server = state();
        std::lock_guard lock(server.stats_mutex);
        server.stats.last_error = message;
    }

    // Read one complete request: headers, then Content-Length bytes of body.
    bool receive_request(SOCKET client, std::string& out) {
        out.clear();
        char buffer[4096];

        for (;;) {
            const int received = recv(client, buffer, sizeof(buffer), 0);
            if (received <= 0) return !out.empty();

            out.append(buffer, static_cast<size_t>(received));
            if (out.size() > max_request_bytes) return false;

            const size_t header_end = debug_harness::http::header_end(out);
            if (header_end == std::string::npos) continue; // headers still incomplete

            const size_t content_length = debug_harness::http::content_length(out);
            if (out.size() >= header_end + content_length) return true;
        }
    }

    void send_all(SOCKET client, const std::string& data) {
        size_t sent = 0;
        while (sent < data.size()) {
            const int wrote = send(client, data.data() + sent, static_cast<int>(data.size() - sent), 0);
            if (wrote <= 0) return;
            sent += static_cast<size_t>(wrote);
        }
    }

    void handle_client(SOCKET client) {
        namespace http = debug_harness::http;
        const auto started = std::chrono::steady_clock::now();

        std::string raw;
        if (!receive_request(client, raw)) {
            send_all(client, http::build_response(400, "application/json",
                                                  debug_harness::routes::error_body("malformed request")));
            return;
        }

        http::request request;
        std::string parse_error;
        if (!http::parse_request(raw, request, parse_error)) {
            send_all(client,
                     http::build_response(400, "application/json", debug_harness::routes::error_body(parse_error)));
            return;
        }

        int status = 200;
        const std::string body = debug_harness::routes::dispatch(request, status);
        send_all(client, http::build_response(status, "application/json", body));

        const auto elapsed = std::chrono::steady_clock::now() - started;
        const double latency_ms = std::chrono::duration<double, std::milli>(elapsed).count();

        auto& server = state();
        std::lock_guard lock(server.stats_mutex);
        ++server.stats.request_count;
        server.stats.last_request = request.method + " " + request.path;
        server.stats.last_latency_ms = latency_ms;
    }

    void accept_loop() {
        auto& server = state();

        while (!server.stopping.load()) {
            fd_set readable;
            FD_ZERO(&readable);
            FD_SET(server.listener, &readable);

            timeval timeout = {};
            timeout.tv_sec = 0;
            timeout.tv_usec = accept_timeout_ms * 1000;

            const int ready = select(0, &readable, nullptr, nullptr, &timeout);
            if (ready <= 0) continue; // timeout, or the listener was closed by stop()

            sockaddr_in from = {};
            int from_length = sizeof(from);
            const SOCKET client = accept(server.listener, reinterpret_cast<sockaddr*>(&from), &from_length);
            if (client == INVALID_SOCKET) continue;

            // One connection at a time, on purpose: it removes every race from the
            // harness itself, and a debug tool has exactly one user.
            handle_client(client);
            closesocket(client);
        }

        server.running.store(false);
    }

    void fail_listener(server_state& server, std::string& out_error, const std::string& message) {
        out_error = message;
        if (server.listener != INVALID_SOCKET) {
            closesocket(server.listener);
            server.listener = INVALID_SOCKET;
        }
        record_error(out_error);
    }
}

namespace debug_harness {

    bool start(unsigned short port, std::string& out_error) {
        out_error.clear();
        auto& server = state();
        std::lock_guard lock(server.mutex);

        if (server.running.load()) {
            out_error = "already running";
            return false;
        }
        // A previous accept thread that exited on its own still needs joining.
        if (server.thread.joinable()) server.thread.join();

        if (!server.winsock_ready) {
            WSADATA data = {};
            const int result = WSAStartup(MAKEWORD(2, 2), &data);
            if (result != 0) {
                out_error = "WSAStartup failed with " + std::to_string(result);
                record_error(out_error);
                return false;
            }
            server.winsock_ready = true;
        }

        server.listener = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (server.listener == INVALID_SOCKET) {
            fail_listener(server, out_error, "socket() failed with " + std::to_string(WSAGetLastError()));
            return false;
        }

        sockaddr_in address = {};
        address.sin_family = AF_INET;
        address.sin_port = htons(port);
        // Loopback only. Never INADDR_ANY: this must not be reachable off the machine.
        inet_pton(AF_INET, "127.0.0.1", &address.sin_addr);

        if (bind(server.listener, reinterpret_cast<sockaddr*>(&address), sizeof(address)) == SOCKET_ERROR) {
            fail_listener(server, out_error,
                          "bind to 127.0.0.1:" + std::to_string(port) + " failed with " +
                              std::to_string(WSAGetLastError()));
            return false;
        }

        if (listen(server.listener, 4) == SOCKET_ERROR) {
            fail_listener(server, out_error, "listen() failed with " + std::to_string(WSAGetLastError()));
            return false;
        }

        // Port 0 asked the OS to pick; report the one it chose.
        sockaddr_in bound = {};
        int bound_length = sizeof(bound);
        unsigned short actual_port = port;
        if (getsockname(server.listener, reinterpret_cast<sockaddr*>(&bound), &bound_length) == 0)
            actual_port = ntohs(bound.sin_port);

        server.port.store(actual_port);
        server.stopping.store(false);
        server.running.store(true);
        {
            std::lock_guard stats_lock(server.stats_mutex);
            server.stats = server_stats();
            server.stats.started_tick_ms = GetTickCount64();
        }

        server.thread = std::thread(accept_loop);
        log(log_level::info, "Debug harness listening on 127.0.0.1:" + std::to_string(actual_port));
        return true;
    }

    void stop() {
        auto& server = state();
        std::lock_guard lock(server.mutex);

        if (!server.running.load() && !server.thread.joinable()) return;

        server.stopping.store(true);

        if (server.listener != INVALID_SOCKET) {
            closesocket(server.listener); // unblocks select()
            server.listener = INVALID_SOCKET;
        }
        if (server.thread.joinable()) server.thread.join();

        server.running.store(false);
        server.port.store(0);
        log(log_level::info, "Debug harness stopped.");
    }

    bool running() {
        return state().running.load();
    }

    unsigned short port() {
        return state().port.load();
    }

    server_stats get_stats() {
        auto& server = state();
        std::lock_guard lock(server.stats_mutex);
        return server.stats;
    }

    bool run_on_game_thread(const std::function<void()>& job, unsigned int timeout_ms) {
        if (in_pump) {
            // Already on the render thread, inside on_frame: queueing would deadlock.
            try {
                if (job) job();
            } catch (...) {
            }
            return true;
        }

        auto posted = std::make_shared<job_state>();
        posted->work = job;
        {
            auto& server = state();
            std::lock_guard lock(server.job_mutex);
            server.jobs.push_back(posted);
        }

        std::unique_lock lock(posted->mutex);
        const bool finished = posted->changed.wait_for(lock, std::chrono::milliseconds(timeout_ms), [&] {
            return posted->current == job_state::phase::done;
        });
        if (finished) return true;

        if (posted->current == job_state::phase::pending) {
            // Withdraw it: the pump skips a cancelled job, so it never runs.
            posted->current = job_state::phase::cancelled;
            return false;
        }

        // The render thread picked it up just as the timeout elapsed. It is running
        // now, possibly against the caller's locals, so it must be waited out.
        posted->changed.wait(lock, [&] { return posted->current == job_state::phase::done; });
        return true;
    }
}

namespace debug_harness::detail {

    void pump_game_thread() {
        auto& server = state();

        std::vector<std::shared_ptr<job_state>> pending;
        {
            std::lock_guard lock(server.job_mutex);
            if (server.jobs.empty()) return; // the common case: one cheap check per frame
            pending.swap(server.jobs);
        }

        const bool was_in_pump = in_pump;
        in_pump = true;
        for (const auto& posted : pending) {
            {
                std::lock_guard lock(posted->mutex);
                if (posted->current != job_state::phase::pending) continue; // timed out and withdrawn
                posted->current = job_state::phase::running;
            }

            if (posted->work) {
                try {
                    posted->work();
                } catch (...) {
                    // A throwing job must never take the render thread with it.
                }
            }

            {
                std::lock_guard lock(posted->mutex);
                posted->current = job_state::phase::done;
            }
            posted->changed.notify_all();
        }
        in_pump = was_in_pump;
    }
}
