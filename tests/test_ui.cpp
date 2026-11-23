#include "harness.hpp"

#include "debug_harness/mem.hpp"
#include "debug_harness/ui.hpp"

#include <cstdint>
#include <format>
#include <string>

// The ui view models, driven without any renderer. Memory comes from local buffers
// reached through "va:" so every read is real but stays inside this process's own data.
namespace {
    namespace ui = debug_harness::ui;

    std::string va(const void* pointer) {
        return std::format("va:0x{:X}", reinterpret_cast<uint64_t>(pointer));
    }

    struct disarm_on_exit {
        ~disarm_on_exit() { debug_harness::mem::arm_writes(false); }
    };
}

TEST(ui_text_buffer_truncates_and_terminates) {
    ui::text_buffer<8> buffer{"@base"};
    CHECK_STR_EQ(buffer.str(), "@base");
    buffer.set("0123456789");
    CHECK_STR_EQ(buffer.str(), "0123456");
    CHECK_EQ(buffer.data[7], '\0');
}

TEST(ui_inspector_paging_collapses_the_path) {
    ui::inspector inspector;
    CHECK(!inspector.has_current());
    CHECK_STR_EQ(inspector.path(), "");

    inspector.navigate("@x", 0x10000);
    CHECK_STR_EQ(inspector.path(), "@x");
    CHECK(inspector.at_anchor());

    CHECK(inspector.page_forward());
    CHECK(inspector.page_forward());
    CHECK_EQ(inspector.current().address(), 0x10200ull);
    CHECK_STR_EQ(inspector.path(), "@x+0x200");

    // Back past the anchor: no expressible form, so the va: fallback.
    CHECK(inspector.page(-0x300));
    CHECK_EQ(inspector.current().delta, -0x100ll);
    CHECK_STR_EQ(inspector.current().path(), "");
    CHECK_STR_EQ(inspector.path(), "va:0xFF00");

    inspector.to_anchor();
    CHECK(inspector.at_anchor());
    CHECK_STR_EQ(inspector.path(), "@x");
}

TEST(ui_inspector_refuses_to_page_below_zero) {
    ui::inspector inspector;
    inspector.navigate("", 0x40);
    CHECK(!inspector.page_back()); // span 0x100 > anchor 0x40
    CHECK_EQ(inspector.current().address(), 0x40ull);
    CHECK_STR_EQ(inspector.path(), "va:0x40");
    CHECK(inspector.page(-0x40));
    CHECK_EQ(inspector.current().address(), 0ull);
}

TEST(ui_inspector_go_reports_errors_and_keeps_history) {
    ui::inspector inspector;
    CHECK(!inspector.go("@no_such_root_anywhere"));
    CHECK(!inspector.error().empty());
    CHECK(!inspector.has_current());

    alignas(8) uint64_t buffer[4] = {1, 2, 3, 4};
    CHECK(inspector.open(va(buffer)));
    CHECK(inspector.error().empty());
    CHECK_STR_EQ(inspector.input.str(), va(buffer));
    CHECK_EQ(inspector.current().address(), reinterpret_cast<uint64_t>(buffer));
}

TEST(ui_inspector_follow_and_back) {
    alignas(8) uint64_t target[4] = {0x11, 0x22, 0x33, 0x44};
    alignas(8) uint64_t source[4] = {0, reinterpret_cast<uint64_t>(&target[0]), 0, 0};

    ui::inspector inspector;
    inspector.set_span_index(0); // 0x40
    CHECK(inspector.go(va(source)));
    CHECK(inspector.tick(1000));
    CHECK(inspector.snapshot().whole_span_readable);

    // Row 0 is null: not followable.
    CHECK(!inspector.follow(0));
    CHECK(inspector.follow(1));
    CHECK_EQ(inspector.current().address(), reinterpret_cast<uint64_t>(&target[0]));
    CHECK_STR_EQ(inspector.path(), va(source) + "[+0x8]");
    CHECK(inspector.can_go_back());

    // Following out of a paged view carries the page offset.
    inspector.page(0x8);
    CHECK_STR_EQ(inspector.path(), va(source) + "[+0x8]+0x8");

    inspector.back();
    CHECK_STR_EQ(inspector.path(), va(source));
    CHECK(!inspector.can_go_back());
    inspector.back(); // no-op at the root of the history
    CHECK(inspector.has_current());
}

TEST(ui_inspector_history_is_capped) {
    ui::inspector inspector;
    for (uint64_t i = 0; i < ui::history_capacity + 10; ++i) inspector.navigate("", 0x1000 + i * 8);
    CHECK_EQ(inspector.history().size(), ui::history_capacity);
    CHECK_EQ(inspector.history().front().anchor, 0x1000ull + 10 * 8);
}

TEST(ui_inspector_refresh_throttle) {
    alignas(8) uint64_t buffer[8] = {};
    ui::inspector inspector;
    CHECK(!inspector.tick(1)); // nothing to read yet
    inspector.navigate(va(buffer), reinterpret_cast<uint64_t>(buffer));
    inspector.set_span_index(0);

    CHECK(inspector.mode() == ui::refresh_mode::four_hz);
    CHECK(inspector.tick(1000)); // navigation forces the first read
    CHECK(!inspector.tick(1100));
    CHECK(!inspector.tick(1249));
    CHECK(inspector.tick(1250));
    CHECK_EQ(inspector.last_refresh_ms(), 1250ull);

    inspector.set_mode(ui::refresh_mode::manual);
    CHECK(!inspector.tick(9000));
    inspector.request_refresh();
    CHECK(inspector.tick(9001));
    CHECK(!inspector.tick(9002));

    inspector.set_span_index(1); // a span change forces a read
    CHECK(inspector.tick(9003));
    inspector.set_span_index(1); // unchanged: does not
    CHECK(!inspector.tick(9004));
    inspector.set_span_index(99);
    CHECK_EQ(inspector.span(), ui::span_choices.back());

    inspector.set_mode(ui::refresh_mode::every_frame);
    CHECK(inspector.tick(9005));
    CHECK(inspector.tick(9005));
    CHECK_EQ(inspector.now_ms(), 9005ull);
}

TEST(ui_inspector_changed_only_and_reset_marks) {
    alignas(8) uint64_t buffer[8] = {};
    ui::inspector inspector;
    inspector.set_span_index(0); // 0x40 = 8 rows
    inspector.navigate(va(buffer), reinterpret_cast<uint64_t>(buffer));
    CHECK(inspector.tick(1000));
    CHECK_EQ(inspector.visible_rows().size(), static_cast<size_t>(8));

    buffer[3] = 0xDEADBEEF;
    inspector.request_refresh();
    CHECK(inspector.tick(1100));
    CHECK_EQ(inspector.snapshot().rows[3].change_count, 1ull);
    CHECK_EQ(inspector.snapshot().rows[3].changed_at_ms, 1100ull);

    inspector.set_changed_only(true);
    const auto& visible = inspector.visible_rows();
    CHECK_EQ(visible.size(), static_cast<size_t>(1));
    CHECK_EQ(visible[0], static_cast<size_t>(3));

    // Classify only what is "drawn".
    inspector.classify_visible(0, visible.size());
    CHECK(inspector.snapshot().rows[3].classified);
    CHECK(!inspector.snapshot().rows[0].classified);

    inspector.reset_change_marks();
    CHECK(inspector.visible_rows().empty());
}

TEST(ui_inspector_hex_lines_cache) {
    alignas(8) uint8_t buffer[0x40] = {'H', 'i'};
    ui::inspector inspector;
    inspector.set_span_index(0);
    inspector.navigate(va(buffer), reinterpret_cast<uint64_t>(buffer));
    inspector.tick(1000);
    CHECK(inspector.hex_lines().empty()); // only built while the hex view is on

    inspector.set_hex_view(true);
    inspector.tick(1001); // throttled re-read, but the cache still builds
    CHECK_EQ(inspector.hex_lines().size(), static_cast<size_t>(4));
    CHECK(inspector.hex_lines()[0].hex.rfind("48 69", 0) == 0);
    CHECK_EQ(inspector.hex_lines()[0].ascii[0], 'H');

    inspector.set_hex_view(false);
    CHECK(inspector.hex_lines().empty());
}

TEST(ui_change_intensity_fades) {
    CHECK(ui::change_intensity(0, 5000) == 0.f);
    CHECK(ui::change_intensity(1000, 1000) == 1.f);
    const float half = ui::change_intensity(1000, 1000 + ui::change_fade_ms / 2);
    CHECK(half > 0.45f && half < 0.55f);
    CHECK(ui::change_intensity(1000, 1000 + ui::change_fade_ms) == 0.f);

    debug_harness::inspect::snapshot snapshot;
    snapshot.rows.resize(4);
    snapshot.rows[1].changed_at_ms = 70;
    snapshot.rows[2].changed_at_ms = 90;
    CHECK_EQ(ui::newest_change_in_line(snapshot, 0x00), 70ull);
    CHECK_EQ(ui::newest_change_in_line(snapshot, 0x10), 90ull);
    CHECK_EQ(ui::newest_change_in_line(snapshot, 0x40), 0ull); // past the end
}

TEST(ui_helpers) {
    CHECK_STR_EQ(ui::hex_bytes({0x48, 0x8B, 0x0C}), "488B0C");
    CHECK(ui::as_float(0x3F800000u) == 1.f);
    CHECK_STR_EQ(ui::kind_name(debug_harness::mem::kind::vtable), "vtable");

    debug_harness::inspect::row row;
    row.readable = true;
    row.classified = true;
    row.kind = debug_harness::mem::kind::heap_ptr;
    CHECK(ui::is_followable(row));
    row.kind = debug_harness::mem::kind::small_int;
    CHECK(!ui::is_followable(row));
}

TEST(ui_watches_add_remove) {
    alignas(8) uint64_t buffer[2] = {};
    ui::watches watches;
    CHECK(watches.empty());
    watches.add(va(buffer));
    watches.add(va(buffer) + "+0x8");
    watches.add("@no_such_root_anywhere");
    CHECK_EQ(watches.size(), static_cast<size_t>(3));

    const auto second = watches.evaluate(1);
    CHECK(second.ok);
    CHECK_EQ(second.address, reinterpret_cast<uint64_t>(buffer) + 8);
    CHECK(!watches.evaluate(2).ok);
    CHECK(!watches.evaluate(7).ok);

    CHECK(watches.remove(0));
    CHECK(!watches.remove(5));
    CHECK_EQ(watches.size(), static_cast<size_t>(2));
    CHECK_STR_EQ(watches.expressions()[0], va(buffer) + "+0x8");
}

TEST(ui_evaluator_on_a_local_buffer) {
    alignas(8) uint64_t target = 0x1234;
    alignas(8) uint64_t holder[2] = {0, reinterpret_cast<uint64_t>(&target)};

    ui::evaluator evaluator;
    CHECK(!evaluator.has_result());
    evaluator.input.set(va(holder) + "[+0x8]");
    evaluator.evaluate();
    CHECK(evaluator.has_result());
    CHECK(evaluator.last_result().ok);
    CHECK_EQ(evaluator.last_result().address, reinterpret_cast<uint64_t>(&target));
    CHECK_EQ(evaluator.last_result().steps.size(), static_cast<size_t>(2));

    evaluator.input.set("va:zz");
    evaluator.evaluate();
    CHECK(!evaluator.last_result().ok);
    evaluator.clear();
    CHECK(!evaluator.has_result());
}

TEST(ui_session_pin_open_and_sections) {
    alignas(8) uint64_t buffer[2] = {};
    ui::session session;
    session.evaluator.input.set(va(buffer));
    session.pin_evaluator_as_watch();
    CHECK_EQ(session.watches.size(), static_cast<size_t>(1));
    CHECK(session.open_evaluator_in_inspector());
    CHECK_STR_EQ(session.inspector.path(), va(buffer));
    session.tick(1000);
    CHECK_EQ(session.inspector.snapshot().sample_count, 1ull);

    int calls = 0;
    session.add_section("Script", [&calls] { calls += 1; });
    session.add_section("Other", [] {});
    session.add_section("Script", [&calls] { calls += 10; }, true); // replaces in place
    CHECK_EQ(session.sections().size(), static_cast<size_t>(2));
    CHECK_STR_EQ(session.sections()[0].name, "Script");
    CHECK(session.sections()[0].default_open);
    session.sections()[0].draw();
    CHECK_EQ(calls, 10);

    CHECK(session.remove_section("Script"));
    CHECK(!session.remove_section("Script"));
    CHECK_EQ(session.sections().size(), static_cast<size_t>(1));
}

TEST(ui_write_log_arm_and_revert) {
    disarm_on_exit disarm;
    alignas(8) uint8_t buffer[8] = {1, 2, 3, 4, 5, 6, 7, 8};
    const uint8_t patch[2] = {0xAA, 0xBB};

    ui::write_log writes;
    writes.set_armed(false);
    CHECK(!writes.armed());
    CHECK_EQ(writes.seconds_left(), 0u);

    size_t index = 0;
    std::string error;
    CHECK(!debug_harness::mem::safe_write(reinterpret_cast<uint64_t>(buffer), patch, sizeof(patch), false, "gui",
                                          index, error));

    writes.set_armed(true);
    CHECK(writes.armed());
    CHECK(writes.seconds_left() > 0u && writes.seconds_left() <= ui::default_arm_seconds);
    CHECK(debug_harness::mem::safe_write(reinterpret_cast<uint64_t>(buffer + 2), patch, sizeof(patch), false, "gui",
                                         index, error));
    CHECK_EQ(buffer[2], 0xAA);

    const auto entries = writes.entries();
    CHECK(index < entries.size());
    CHECK_EQ(entries[index].address, reinterpret_cast<uint64_t>(buffer + 2));
    CHECK_STR_EQ(ui::hex_bytes(entries[index].old_bytes), "0304");

    // Revert ignores the arm state: undoing damage must always be possible.
    writes.set_armed(false);
    CHECK(writes.revert(index));
    CHECK(writes.last_error().empty());
    CHECK_EQ(buffer[2], 3);
    CHECK_EQ(buffer[3], 4);
    CHECK(writes.entries()[index].reverted);

    CHECK(!writes.revert(index));
    CHECK(!writes.last_error().empty());
    CHECK(!writes.revert(1'000'000));
}

TEST(ui_server_control_port_clamps) {
    ui::server_control server;
    CHECK_EQ(server.port(), 27015);
    server.set_port(80);
    CHECK_EQ(server.port(), 1024);
    server.set_port(70000);
    CHECK_EQ(server.port(), 65535);
    CHECK(!server.running());
    CHECK_EQ(server.listening_port(), static_cast<unsigned short>(0));
}
