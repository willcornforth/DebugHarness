#pragma once

#include <cstdint>
#include <functional>
#include <string>

// Loopback HTTP listener.
//
// Off by default: nothing listens until the consumer calls start(), so linking the
// library costs nothing at load time. The socket is bound to 127.0.0.1 only, never
// INADDR_ANY. One connection is served at a time, on the server's own thread; request
// routing is debug_harness::routes::dispatch.
namespace debug_harness {

    constexpr unsigned short default_port = 27015;

    // Bind, listen, and spawn the accept thread. False with out_error set on failure
    // (port in use is the common one); the listener stays off in that case.
    // Port 0 binds an ephemeral port; port() then reports the one the OS chose.
    bool start(unsigned short port, std::string& out_error);

    // Close the socket and join the thread. Safe to call when not running.
    void stop();

    bool running();

    // The bound port while running, 0 otherwise.
    unsigned short port();

    struct server_stats {
        uint64_t request_count = 0;
        std::string last_request; // "GET /chain"
        double last_latency_ms = 0.0;
        std::string last_error;
        uint64_t started_tick_ms = 0; // GetTickCount64 at start(); 0 when never started
    };

    server_stats get_stats();

    // --- host-thread marshalling ---------------------------------------------
    //
    // Anything that touches host state must run on the host's render thread. A route
    // handler posts a job here and waits; on_frame() drains the queue once per frame.
    //
    // Returns true once `job` has run (a job that throws still counts as run; the
    // exception is swallowed so it cannot take the render thread down).
    //
    // Returns false when the host did not pick the job up within `timeout_ms`, which is
    // how a frozen or not-rendering host becomes an HTTP 504 instead of a hung harness.
    // A false return guarantees the job did not run and never will: it is withdrawn
    // from the queue, so capturing locals by reference is safe. If the host picks the
    // job up just as the timeout elapses, this waits for it to finish and returns true.
    //
    // Called from inside a job that on_frame() is running, the job runs inline rather
    // than deadlocking. Do not call it from the render thread outside on_frame: nothing
    // can drain the queue while that thread waits, so it always times out.
    bool run_on_game_thread(const std::function<void()>& job, unsigned int timeout_ms = 2000);
}
