#pragma once

#include <string>
#include <utility>
#include <vector>

#include "debug_harness/harness.hpp"

// Internal view of the host-registered routes (storage lives in host.cpp). The
// built-in route table consults this after its own routes miss.
namespace debug_harness::detail {

    // Copies the handler out under the lock, so the caller can run it without holding
    // the registry mutex (a handler may itself call register_route).
    bool find_route(const std::string& path, route_handler& out_handler);

    // {path, description}, sorted by path.
    std::vector<std::pair<std::string, std::string>> list_routes();
}
