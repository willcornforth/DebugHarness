#pragma once

// Seam between on_frame (host.cpp) and the server's game-thread job queue. on_frame is
// called on the host's render thread and drains whatever run_on_game_thread posted.
namespace debug_harness::detail {
    void pump_game_thread();
}
