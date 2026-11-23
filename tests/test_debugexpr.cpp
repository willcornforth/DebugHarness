#include "harness.hpp"

#include "debug_harness/expr.hpp"

#include <map>
#include <string>

namespace {

    constexpr uint64_t fake_module_base = 0x00007FF6A0000000ull;
    constexpr uint64_t fake_preferred_base = 0x0000000140000000ull;

    struct fake_env : debug_harness::expr::env {
        std::map<std::string, uint64_t> roots;
        std::map<std::string, uint64_t> symbols;
        std::map<uint64_t, uint64_t> reads; // address -> qword; absent means unreadable

        uint64_t module_base() const override { return fake_module_base; }
        uint64_t preferred_base() const override { return fake_preferred_base; }

        bool root(const std::string& name, uint64_t& out_value, std::string& out_note) const override {
            const auto found = roots.find(name);
            if (found == roots.end()) return false;
            out_value = found->second;
            out_note = "fake root";
            return true;
        }

        bool symbol(const std::string& qualified, uint64_t& out_value) const override {
            const auto found = symbols.find(qualified);
            if (found == symbols.end()) return false;
            out_value = found->second;
            return true;
        }

        bool read_u64(uint64_t address, uint64_t& out_value, std::string& out_note) const override {
            const auto found = reads.find(address);
            if (found == reads.end()) {
                out_note = "unreadable";
                return false;
            }
            out_value = found->second;
            out_note = "fake read";
            return true;
        }
    };

    fake_env make_env() {
        fake_env env;
        env.roots["base"] = fake_module_base;
        env.roots["local.player"] = 0x0000020000001000ull;
        env.symbols["Player::OFF_INVENTORY"] = 0x130;
        env.symbols["DamageManager::OFF_MAIN_HITZONE"] = 0x60;
        env.symbols["OFF_SCRIPT_CONTEXT"] = 0x217B6B8;
        return env;
    }
}

TEST(expr_va_root_resolves_to_itself) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("va:0x7FF6ABCD1234", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x00007FF6ABCD1234ull);
    CHECK_EQ(result.steps.size(), static_cast<size_t>(1));
    CHECK(!result.steps[0].deref);
    CHECK(result.steps[0].ok);
}

TEST(expr_rva_root_adds_the_module_base) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("rva:0x22C78F8", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, fake_module_base + 0x22C78F8ull);
}

TEST(expr_ida_root_rebases_through_the_preferred_base) {
    const auto env = make_env();
    // ida:0x1422C78F8 == preferred base + 0x22C78F8
    const auto result = debug_harness::expr::evaluate("ida:0x1422C78F8", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, fake_module_base + 0x22C78F8ull);
}

TEST(expr_ida_and_rva_agree_for_the_same_offset) {
    const auto env = make_env();
    const auto via_rva = debug_harness::expr::evaluate("rva:0x22C78F8", env);
    const auto via_ida = debug_harness::expr::evaluate("ida:0x1422C78F8", env);
    CHECK(via_rva.ok);
    CHECK(via_ida.ok);
    CHECK_EQ(via_rva.address, via_ida.address);
}

TEST(expr_ida_below_the_preferred_base_is_an_error) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("ida:0x1000", env);
    CHECK(!result.ok);
    CHECK(result.error.find("preferred image base") != std::string::npos);
}

TEST(expr_named_root_resolves_from_the_env) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("@local.player", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x0000020000001000ull);
    CHECK_STR_EQ(result.steps[0].label, "@local.player");
}

TEST(expr_unknown_named_root_is_an_error) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("@nope", env);
    CHECK(!result.ok);
    CHECK(result.error.find("unknown root") != std::string::npos);
    CHECK_EQ(result.error_at, static_cast<size_t>(0));
}

TEST(expr_missing_root_is_an_error) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("0x130", env);
    CHECK(!result.ok);
    CHECK(result.error.find("must start with") != std::string::npos);
}

TEST(expr_empty_expression_is_an_error) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("", env);
    CHECK(!result.ok);
}

TEST(expr_whitespace_only_expression_is_an_error) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("   ", env);
    CHECK(!result.ok);
}

TEST(expr_hex_without_0x_prefix_is_an_error) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("va:1234", env);
    CHECK(!result.ok);
    CHECK(result.error.find("0x") != std::string::npos);
}

TEST(expr_plain_addend_adds_without_dereferencing) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("@local.player+0x130", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x0000020000001130ull);
    CHECK_EQ(result.steps.size(), static_cast<size_t>(2));
    CHECK(!result.steps[1].deref);
    CHECK_STR_EQ(result.steps[1].label, "+0x130");
}

TEST(expr_multiple_addends_accumulate_left_to_right) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("va:0x1000+0x10+0x20+0x4", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x1034ull);
    CHECK_EQ(result.steps.size(), static_cast<size_t>(4));
}

TEST(expr_whitespace_around_operators_is_tolerated) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("  va:0x1000 + 0x10 ", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x1010ull);
}

TEST(expr_dangling_plus_is_an_error) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("va:0x1000+", env);
    CHECK(!result.ok);
}

TEST(expr_trailing_garbage_is_an_error_with_its_offset) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("va:0x1000 junk", env);
    CHECK(!result.ok);
    CHECK_EQ(result.error_at, static_cast<size_t>(10));
}

TEST(expr_root_step_records_the_env_note) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("@base", env);
    CHECK(result.ok);
    CHECK_STR_EQ(result.steps[0].note, "fake root");
}

TEST(expr_address_arithmetic_wraps_rather_than_overflowing) {
    const auto env = make_env();
    const auto result = debug_harness::expr::evaluate("va:0xFFFFFFFFFFFFFFFF+0x2", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x1ull);
}

TEST(expr_bracket_addend_dereferences) {
    auto env = make_env();
    // character + 0x130 holds the damage manager pointer.
    env.reads[0x0000020000001130ull] = 0x0000020000009000ull;

    const auto result = debug_harness::expr::evaluate("@local.player[+0x130]", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x0000020000009000ull);
    CHECK_EQ(result.steps.size(), static_cast<size_t>(2));
    CHECK(result.steps[1].deref);
    CHECK_EQ(result.steps[1].address, 0x0000020000001130ull);
    CHECK_EQ(result.steps[1].value, 0x0000020000009000ull);
    CHECK_STR_EQ(result.steps[1].label, "[+0x130]");
}

TEST(expr_empty_brackets_dereference_with_no_addend) {
    auto env = make_env();
    env.reads[0x0000020000001000ull] = 0x00000200000AA000ull;

    const auto result = debug_harness::expr::evaluate("@local.player[]", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x00000200000AA000ull);
    CHECK(result.steps[1].deref);
    CHECK_STR_EQ(result.steps[1].label, "[]");
}

TEST(expr_the_documented_double_deref_health_chain_resolves) {
    auto env = make_env();
    env.reads[0x0000020000001130ull] = 0x0000020000009000ull; // character+0x130 -> DamageManager
    env.reads[0x0000020000009060ull] = 0x000002000000B000ull; // dm+0x60 -> hitzone array
    env.reads[0x000002000000B000ull] = 0x000002000000C000ull; // *array   -> main hitzone

    const auto result = debug_harness::expr::evaluate("@local.player[+0x130][+0x60][]+0x3C", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x000002000000C03Cull);
    CHECK_EQ(result.steps.size(), static_cast<size_t>(5));
}

TEST(expr_a_failed_deref_reports_which_step_broke_and_keeps_the_trace) {
    auto env = make_env();
    env.reads[0x0000020000001130ull] = 0x0000020000009000ull;
    // dm+0x60 is deliberately absent from `reads`, i.e. unreadable.

    const auto result = debug_harness::expr::evaluate("@local.player[+0x130][+0x60]", env);
    CHECK(!result.ok);
    CHECK(result.error.find("could not read") != std::string::npos);
    // The trace still shows the root, the first (successful) deref, and the failure.
    CHECK_EQ(result.steps.size(), static_cast<size_t>(3));
    CHECK(result.steps[1].ok);
    CHECK(!result.steps[2].ok);
    CHECK_EQ(result.steps[2].address, 0x0000020000009060ull);
    CHECK_STR_EQ(result.steps[2].note, "unreadable");
}

TEST(expr_named_symbol_addend_resolves) {
    auto env = make_env();
    const auto result = debug_harness::expr::evaluate("@local.player+Player::OFF_INVENTORY", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x0000020000001130ull);
    CHECK_STR_EQ(result.steps[1].label, "+Player::OFF_INVENTORY (0x130)");
}

TEST(expr_named_symbol_addend_works_inside_brackets) {
    auto env = make_env();
    env.reads[0x0000020000001130ull] = 0x0000020000009000ull;

    const auto result = debug_harness::expr::evaluate("@local.player[+Player::OFF_INVENTORY]", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x0000020000009000ull);
}

TEST(expr_bare_root_symbol_name_resolves) {
    auto env = make_env();
    const auto result = debug_harness::expr::evaluate("@base+OFF_SCRIPT_CONTEXT", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, fake_module_base + 0x217B6B8ull);
}

TEST(expr_unknown_symbol_is_an_error) {
    auto env = make_env();
    const auto result = debug_harness::expr::evaluate("@base+Nope::OFF_MISSING", env);
    CHECK(!result.ok);
    CHECK(result.error.find("unknown offset") != std::string::npos);
}

TEST(expr_unclosed_bracket_is_an_error) {
    auto env = make_env();
    const auto result = debug_harness::expr::evaluate("@local.player[+0x130", env);
    CHECK(!result.ok);
    CHECK(result.error.find("']'") != std::string::npos);
}

TEST(expr_bracket_without_plus_before_the_addend_is_an_error) {
    auto env = make_env();
    const auto result = debug_harness::expr::evaluate("@local.player[0x130]", env);
    CHECK(!result.ok);
}

TEST(expr_closing_bracket_without_an_opening_one_is_an_error) {
    auto env = make_env();
    const auto result = debug_harness::expr::evaluate("@local.player]", env);
    CHECK(!result.ok);
}

TEST(expr_mixed_deref_and_plain_addends_apply_left_to_right) {
    auto env = make_env();
    env.reads[0x0000020000001010ull] = 0x0000030000000000ull;

    const auto result = debug_harness::expr::evaluate("@local.player+0x10[]+0x8", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x0000030000000008ull);
}

TEST(expr_whitespace_inside_brackets_is_tolerated) {
    auto env = make_env();
    env.reads[0x0000020000001130ull] = 0x0000020000009000ull;

    const auto result = debug_harness::expr::evaluate("@local.player [ + 0x130 ]", env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x0000020000009000ull);
}
