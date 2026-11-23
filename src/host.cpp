#include "debug_harness/harness.hpp"

#include <algorithm>
#include <map>
#include <mutex>

#include "internal/game_thread.hpp"
#include "internal/route_registry.hpp"

namespace {

    debug_harness::host_config& storage() {
        static debug_harness::host_config config;
        return config;
    }

    struct route {
        debug_harness::route_handler handler;
        std::string description;
    };

    struct route_table {
        std::mutex mutex;
        std::map<std::string, route> routes; // ordered, so list_routes is sorted for free
    };

    route_table& routes() {
        static route_table table;
        return table;
    }
}

namespace debug_harness {

    void configure(host_config config) {
        storage() = std::move(config);
    }

    const host_config& config() {
        return storage();
    }

    void on_frame() {
        detail::pump_game_thread();
    }

    void register_route(const std::string& path, route_handler handler, const std::string& description) {
        // A path that cannot match a parsed request (parse_request rejects paths without a
        // leading '/') or a null handler would only ever produce a confusing 500.
        if (path.empty() || path.front() != '/' || !handler) return;
        auto& table = routes();
        std::lock_guard lock(table.mutex);
        table.routes[path] = route{std::move(handler), description};
    }

    void unregister_route(const std::string& path) {
        auto& table = routes();
        std::lock_guard lock(table.mutex);
        table.routes.erase(path);
    }

    void log(log_level level, const std::string& message) {
        const auto& sink = storage().log;
        if (sink) sink(level, message);
    }
}

namespace debug_harness::detail {

    bool find_route(const std::string& path, route_handler& out_handler) {
        auto& table = routes();
        std::lock_guard lock(table.mutex);
        const auto found = table.routes.find(path);
        if (found == table.routes.end()) return false;
        out_handler = found->second.handler;
        return true;
    }

    std::vector<std::pair<std::string, std::string>> list_routes() {
        auto& table = routes();
        std::lock_guard lock(table.mutex);
        std::vector<std::pair<std::string, std::string>> out;
        out.reserve(table.routes.size());
        for (const auto& [path, route] : table.routes)
            out.emplace_back(path, route.description);
        return out;
    }
}
