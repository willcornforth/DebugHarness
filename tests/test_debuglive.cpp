#include "harness.hpp"

#include "debug_harness/expr.hpp"
#include "debug_harness/harness.hpp"
#include "debug_harness/live.hpp"

#include <cstdio>
#include <string>
#include <vector>

namespace {
    bool fake_root_resolver(const std::string& name, uint64_t& out_value, std::string& out_note) {
        if (name == "fake") {
            out_value = 0x1234;
            out_note = "installed fake";
            return true;
        }
        return false;
    }

    std::vector<debug_harness::root_entry> fake_root_enumerator() {
        return {debug_harness::root_entry{"fake", 0x1234, true, "installed fake"}};
    }

    bool fake_symbol_resolver(const std::string& qualified, uint64_t& out_value) {
        if (qualified == "Player::OFF_INVENTORY") {
            out_value = 0x130;
            return true;
        }
        return false;
    }

    // Installs the fake host for one test and restores an empty config afterwards, so
    // no test leaks host callbacks into the next.
    struct fake_host {
        fake_host() {
            debug_harness::host_config config;
            config.resolve_root = fake_root_resolver;
            config.enumerate_roots = fake_root_enumerator;
            config.resolve_symbol = fake_symbol_resolver;
            debug_harness::configure(std::move(config));
        }
        ~fake_host() { debug_harness::configure({}); }
    };
}

TEST(live_reports_the_main_module) {
    debug_harness::configure({});
    CHECK(debug_harness::live::module_base() != 0);
    CHECK(debug_harness::live::module_image_size() > 0x1000);
    CHECK(debug_harness::live::module_name().find("debug_harness_tests") != std::string::npos);
}

TEST(live_preferred_base_is_page_aligned_and_nonzero) {
    const auto preferred = debug_harness::live::module_preferred_base();
    CHECK(preferred != 0);
    CHECK_EQ(preferred & 0xFFFull, static_cast<uint64_t>(0));
}

TEST(describe_round_trips_va_to_rva_and_back) {
    const uint64_t va = debug_harness::live::module_base() + 0x1000;
    const auto info = debug_harness::live::describe(va);
    CHECK(info.in_module);
    CHECK_EQ(info.va, va);
    CHECK_EQ(info.rva, static_cast<uint64_t>(0x1000));
    CHECK_EQ(info.ida, debug_harness::live::module_preferred_base() + 0x1000);
}

TEST(describe_marks_an_address_outside_the_module) {
    int local = 0;
    const auto info = debug_harness::live::describe(reinterpret_cast<uint64_t>(&local));
    CHECK(!info.in_module);
    CHECK_EQ(info.rva, static_cast<uint64_t>(0));
    CHECK_EQ(info.ida, static_cast<uint64_t>(0));
}

TEST(describe_carries_the_region_info) {
    const auto info = debug_harness::live::describe(reinterpret_cast<uint64_t>(&debug_harness::live::module_base));
    CHECK(info.region.valid);
    CHECK(info.region.executable);
}

TEST(live_env_resolves_host_symbols) {
    fake_host host;
    uint64_t value = 0;
    CHECK(debug_harness::live::env().symbol("Player::OFF_INVENTORY", value));
    CHECK_EQ(value, static_cast<uint64_t>(0x130));
    CHECK(!debug_harness::live::env().symbol("Nope::MISSING", value));
}

TEST(live_env_resolves_no_symbols_without_a_host) {
    debug_harness::configure({});
    uint64_t value = 0;
    CHECK(!debug_harness::live::env().symbol("Player::OFF_INVENTORY", value));
}

TEST(live_env_module_and_preferred_base_match_the_accessors) {
    CHECK_EQ(debug_harness::live::env().module_base(), debug_harness::live::module_base());
    CHECK_EQ(debug_harness::live::env().preferred_base(), debug_harness::live::module_preferred_base());
}

TEST(live_env_reads_readable_memory_and_refuses_the_rest) {
    const uint64_t source = 0x0123456789ABCDEFull;
    uint64_t value = 0;
    std::string note;
    CHECK(debug_harness::live::env().read_u64(reinterpret_cast<uint64_t>(&source), value, note));
    CHECK_EQ(value, source);
    CHECK(!note.empty());

    CHECK(!debug_harness::live::env().read_u64(0x10ull, value, note));
    CHECK(!note.empty());
}

// Was "roots are empty until installed": the built-in @base is now always present,
// so without a host the list is exactly that one entry and nothing else resolves.
TEST(live_roots_hold_only_base_without_a_host) {
    debug_harness::configure({});
    const auto roots = debug_harness::live::roots();
    CHECK_EQ(roots.size(), static_cast<size_t>(1));
    CHECK_STR_EQ(roots[0].name, "base");

    uint64_t value = 0;
    std::string note;
    CHECK(!debug_harness::live::env().root("anything", value, note));
    CHECK(!note.empty());
}

TEST(live_host_roots_resolve_through_the_env) {
    fake_host host;

    uint64_t value = 0;
    std::string note;
    CHECK(debug_harness::live::env().root("fake", value, note));
    CHECK_EQ(value, static_cast<uint64_t>(0x1234));
    CHECK_STR_EQ(note, "installed fake");
    CHECK(!debug_harness::live::env().root("missing", value, note));

    const auto roots = debug_harness::live::roots();
    CHECK_EQ(roots.size(), static_cast<size_t>(2)); // @base + the host's one
    CHECK_STR_EQ(roots[0].name, "base");
    CHECK_STR_EQ(roots[1].name, "fake");
}

TEST(live_env_drives_a_full_expression_evaluation) {
    fake_host host;

    const uint64_t target = 0xCAFEBABEull;
    const uint64_t pointer_to_target = reinterpret_cast<uint64_t>(&target);

    char expression[128] = {};
    _snprintf_s(expression, sizeof(expression), _TRUNCATE, "va:0x%llX[]",
                static_cast<unsigned long long>(pointer_to_target));

    const auto result = debug_harness::expr::evaluate(expression, debug_harness::live::env());
    CHECK(result.ok);
    CHECK_EQ(result.address, target);
}
