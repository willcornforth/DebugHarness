#include "debug_harness_panel.hpp"

#include "imgui.h"

#include <chrono>
#include <cstdint>
#include <string>
#include <vector>

#include "debug_harness/live.hpp"
#include "debug_harness/mem.hpp"
#include "debug_harness/server.hpp"

// Presentation only. Every piece of state and every decision lives in ui::session
// (include/debug_harness/ui.hpp); this file turns it into ImGui calls.
namespace {

    namespace ui = debug_harness::ui;

    const ImVec4 error_colour(1.f, 0.4f, 0.4f, 1.f);
    const ImVec4 ok_colour(0.5f, 1.f, 0.5f, 1.f);

    unsigned long long ull(uint64_t value) {
        return static_cast<unsigned long long>(value);
    }

    uint64_t now_ms() {
        using namespace std::chrono;
        return static_cast<uint64_t>(duration_cast<milliseconds>(steady_clock::now().time_since_epoch()).count());
    }

    ImVec4 kind_colour(debug_harness::mem::kind value) {
        using kind = debug_harness::mem::kind;
        switch (value) {
        case kind::code:
            return ImVec4(0.55f, 0.75f, 1.00f, 1.f);
        case kind::vtable:
            return ImVec4(0.85f, 0.60f, 1.00f, 1.f);
        case kind::heap_ptr:
            return ImVec4(0.45f, 0.90f, 0.90f, 1.f);
        case kind::stack_ptr:
            return ImVec4(1.00f, 0.75f, 0.40f, 1.f);
        case kind::ascii:
            return ImVec4(0.55f, 0.95f, 0.55f, 1.f);
        case kind::float_pair:
            return ImVec4(0.90f, 0.90f, 0.50f, 1.f);
        case kind::small_int:
            return ImVec4(0.75f, 0.75f, 0.75f, 1.f);
        case kind::null:
            return ImVec4(0.45f, 0.45f, 0.45f, 1.f);
        default:
            return ImVec4(0.65f, 0.65f, 0.65f, 1.f);
        }
    }

    // Tint a row that changed recently, fading out over ui::change_fade_ms.
    void tint_if_recently_changed(uint64_t changed_at_ms, uint64_t now) {
        const float intensity = ui::change_intensity(changed_at_ms, now);
        if (intensity <= 0.f) return;
        ImGui::TableSetBgColor(ImGuiTableBgTarget_RowBg0,
                               ImGui::GetColorU32(ImVec4(0.85f, 0.60f, 0.10f, 0.55f * intensity)));
    }

    // One evaluation as a per-step table. Shared by Evaluate and deliberately identical
    // to what GET /chain returns.
    void draw_evaluation(const debug_harness::expr::result& result) {
        if (!result.ok) {
            ImGui::TextColored(error_colour, "error: %s (at %zu)", result.error.c_str(), result.error_at);
        } else {
            const auto info = debug_harness::live::describe(result.address);
            ImGui::TextColored(ok_colour, "= 0x%llX", ull(result.address));
            if (info.in_module) {
                ImGui::SameLine();
                ImGui::TextDisabled("(rva 0x%llX / ida 0x%llX)", ull(info.rva), ull(info.ida));
            }
        }

        if (result.steps.empty()) return;

        if (ImGui::BeginTable("steps", 4,
                              ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_SizingStretchProp)) {
            ImGui::TableSetupColumn("step");
            ImGui::TableSetupColumn("address");
            ImGui::TableSetupColumn("value");
            ImGui::TableSetupColumn("note");
            ImGui::TableHeadersRow();

            for (const auto& step : result.steps) {
                ImGui::TableNextRow();
                ImGui::TableNextColumn();
                if (step.ok)
                    ImGui::TextUnformatted(step.label.c_str());
                else
                    ImGui::TextColored(error_colour, "%s", step.label.c_str());

                ImGui::TableNextColumn();
                ImGui::Text("0x%llX", ull(step.address));

                ImGui::TableNextColumn();
                if (step.deref && !step.ok)
                    ImGui::TextDisabled("--");
                else
                    ImGui::Text("0x%llX", ull(step.value));

                ImGui::TableNextColumn();
                ImGui::TextDisabled("%s", step.note.c_str());
            }
            ImGui::EndTable();
        }
    }

    // --- structure inspector -------------------------------------------------

    // Returns the snapshot row to follow, or -1. Following is deferred to the caller:
    // it replaces the snapshot this table is iterating.
    long long draw_qword_table(ui::inspector& inspector, uint64_t now) {
        const auto& visible = inspector.visible_rows();
        long long follow_row = -1;

        if (!ImGui::BeginTable("inspectq", 7,
                               ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                   ImGuiTableFlags_SizingStretchProp,
                               ImVec2(0, 320)))
            return follow_row;

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("off", ImGuiTableColumnFlags_WidthFixed, 52.f);
        ImGui::TableSetupColumn("qword", ImGuiTableColumnFlags_WidthFixed, 140.f);
        ImGui::TableSetupColumn("i32 lo/hi");
        ImGui::TableSetupColumn("f32 lo/hi");
        ImGui::TableSetupColumn("chg", ImGuiTableColumnFlags_WidthFixed, 40.f);
        ImGui::TableSetupColumn("looks like");
        ImGui::TableSetupColumn("", ImGuiTableColumnFlags_WidthFixed, 26.f);
        ImGui::TableHeadersRow();

        // Clipped, because classification is lazy and only the drawn rows pay for it.
        // At the largest span that is ~15 rows probed instead of 512.
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(visible.size()));
        while (clipper.Step()) {
            inspector.classify_visible(static_cast<size_t>(clipper.DisplayStart),
                                       static_cast<size_t>(clipper.DisplayEnd));
            for (int line = clipper.DisplayStart; line < clipper.DisplayEnd; ++line) {
                const size_t i = visible[static_cast<size_t>(line)];
                const auto& row = inspector.snapshot().rows[i];

                ImGui::TableNextRow();
                tint_if_recently_changed(row.changed_at_ms, now);
                ImGui::PushID(static_cast<int>(i));

                ImGui::TableNextColumn();
                ImGui::Text("+%llX", ull(row.offset));
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("0x%llX", ull(row.address));

                ImGui::TableNextColumn();
                if (row.readable)
                    ImGui::Text("%016llX", ull(row.value));
                else
                    ImGui::TextDisabled("----------------");

                const auto low = static_cast<uint32_t>(row.value);
                const auto high = static_cast<uint32_t>(row.value >> 32);

                ImGui::TableNextColumn();
                if (row.readable) ImGui::Text("%d / %d", static_cast<int32_t>(low), static_cast<int32_t>(high));

                ImGui::TableNextColumn();
                if (row.readable)
                    ImGui::Text("%.4g / %.4g", static_cast<double>(ui::as_float(low)),
                                static_cast<double>(ui::as_float(high)));

                ImGui::TableNextColumn();
                if (row.change_count)
                    ImGui::TextColored(ImVec4(1.f, 0.8f, 0.3f, 1.f), "%llu", ull(row.change_count));
                else
                    ImGui::TextDisabled("-");

                ImGui::TableNextColumn();
                ImGui::TextColored(kind_colour(row.kind), "%s", row.kind_text.c_str());
                if (row.vtable_slots && ImGui::IsItemHovered())
                    ImGui::SetTooltip("%llu code pointers follow", ull(row.vtable_slots));

                ImGui::TableNextColumn();
                const bool followable = ui::is_followable(row);
                if (followable && ImGui::SmallButton(">")) follow_row = static_cast<long long>(i);
                if (followable && ImGui::IsItemHovered()) ImGui::SetTooltip("Follow this pointer");

                ImGui::PopID();
            }
        }

        ImGui::EndTable();

        if (visible.empty() && !inspector.snapshot().rows.empty())
            ImGui::TextDisabled("Nothing has changed yet. Untick the filter, or act in the host.");
        return follow_row;
    }

    void draw_hex_table(const ui::inspector& inspector, uint64_t now) {
        if (!ImGui::BeginTable("inspecth", 3,
                               ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY |
                                   ImGuiTableFlags_SizingFixedFit,
                               ImVec2(0, 320)))
            return;

        ImGui::TableSetupScrollFreeze(0, 1);
        ImGui::TableSetupColumn("off");
        ImGui::TableSetupColumn("bytes");
        ImGui::TableSetupColumn("ascii");
        ImGui::TableHeadersRow();

        const auto& lines = inspector.hex_lines();
        ImGuiListClipper clipper;
        clipper.Begin(static_cast<int>(lines.size()));
        while (clipper.Step()) {
            for (int index = clipper.DisplayStart; index < clipper.DisplayEnd; ++index) {
                const auto& line = lines[static_cast<size_t>(index)];
                ImGui::TableNextRow();
                tint_if_recently_changed(ui::newest_change_in_line(inspector.snapshot(), line.offset), now);

                ImGui::TableNextColumn();
                ImGui::Text("+%03llX", ull(line.offset));

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(line.hex.c_str());

                ImGui::TableNextColumn();
                ImGui::TextUnformatted(line.ascii.c_str());
            }
        }

        ImGui::EndTable();
    }

    void draw_inspector(ui::inspector& inspector) {
        // --- address bar ---
        ImGui::SetNextItemWidth(-136);
        const bool submitted = ImGui::InputText("##inspectaddr", inspector.input.data, inspector.input.capacity,
                                                ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::SameLine();
        if (ImGui::Button("Go", ImVec2(60, 0)) || submitted) inspector.go();

        ImGui::SameLine();
        ImGui::BeginDisabled(!inspector.can_go_back());
        if (ImGui::Button("Back", ImVec2(60, 0))) inspector.back();
        ImGui::EndDisabled();

        if (!inspector.error().empty()) ImGui::TextColored(error_colour, "%s", inspector.error().c_str());

        if (!inspector.has_current()) {
            ImGui::TextDisabled("Enter an address expression and press Go, e.g. @base");
            return;
        }

        // --- navigation and span ---
        if (ImGui::Button("<< page")) inspector.page_back();
        ImGui::SameLine();
        if (ImGui::Button("page >>")) inspector.page_forward();
        ImGui::SameLine();
        ImGui::BeginDisabled(inspector.at_anchor());
        if (ImGui::Button("anchor")) inspector.to_anchor();
        ImGui::EndDisabled();
        if (ImGui::IsItemHovered(ImGuiHoveredFlags_AllowWhenDisabled))
            ImGui::SetTooltip("Back to the address the expression resolves to");

        ImGui::SameLine();
        ImGui::SetNextItemWidth(90);
        int span_index = inspector.span_index();
        if (ImGui::Combo("##span", &span_index, ui::span_labels.data(), static_cast<int>(ui::span_labels.size())))
            inspector.set_span_index(span_index);

        ImGui::SameLine();
        ImGui::SetNextItemWidth(110);
        int mode = static_cast<int>(inspector.mode());
        if (ImGui::Combo("##refresh", &mode, ui::refresh_mode_labels.data(),
                         static_cast<int>(ui::refresh_mode_labels.size())))
            inspector.set_mode(static_cast<ui::refresh_mode>(mode));

        ImGui::SameLine();
        // An explicit Refresh is also the way to say "the classifications may be stale".
        if (ImGui::Button("Refresh")) inspector.request_refresh(true);

        // --- re-read ---
        //
        // The panel's only tick (it is session::tick for this model): after the controls,
        // so a Refresh click or span change shows this frame.
        const uint64_t now = now_ms();
        inspector.tick(now);

        // --- where we are ---
        const auto& current = inspector.current();
        const auto info = debug_harness::live::describe(current.address());
        ImGui::Text("0x%llX", ull(current.address()));
        if (info.in_module) {
            ImGui::SameLine();
            ImGui::TextDisabled("rva 0x%llX / ida 0x%llX", ull(info.rva), ull(info.ida));
        }
        ImGui::SameLine();
        if (info.region.valid) {
            const std::string origin = ui::region_origin(info.region);
            ImGui::TextDisabled("| %s%s%s | %zu/%zu rows readable", origin.c_str(),
                                info.region.section_name.empty() ? "" : " ", info.region.section_name.c_str(),
                                inspector.snapshot().readable_rows, inspector.snapshot().rows.size());
        } else {
            ImGui::TextColored(error_colour, "| unmapped");
        }

        // The expression that reaches here, which is the thing worth keeping: it goes
        // straight into the host's offset table or a /chain call.
        const std::string path = inspector.path();
        if (ImGui::SmallButton("Copy path")) ImGui::SetClipboardText(path.c_str());
        ImGui::SameLine();
        ImGui::TextWrapped("%s", path.c_str());

        // --- view options ---
        bool hex_view = inspector.hex_view();
        if (ImGui::Checkbox("Hex dump", &hex_view)) {
            inspector.set_hex_view(hex_view);
            inspector.tick(now); // build the hex-line cache now rather than next frame
        }
        ImGui::SameLine();
        ImGui::BeginDisabled(inspector.hex_view());
        bool changed_only = inspector.changed_only();
        if (ImGui::Checkbox("Only rows that changed", &changed_only)) inspector.set_changed_only(changed_only);
        ImGui::EndDisabled();
        ImGui::SameLine();
        if (ImGui::Button("Reset change marks")) inspector.reset_change_marks();
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Clear the counters, do something in the host, then look again.");

        // --- the dump ---
        if (inspector.hex_view()) {
            draw_hex_table(inspector, now);
        } else {
            const long long follow_row = draw_qword_table(inspector, now);
            // Deferred: follow() replaces the snapshot and the history entry.
            if (follow_row >= 0) inspector.follow(static_cast<size_t>(follow_row));
        }
    }

    // --- sections ------------------------------------------------------------

    void draw_server(ui::server_control& server) {
        const bool running = server.running();

        ImGui::BeginDisabled(running);
        ImGui::SetNextItemWidth(120);
        int port = server.port();
        if (ImGui::InputInt("Port", &port)) server.set_port(port);
        ImGui::EndDisabled();

        if (!running) {
            if (ImGui::Button("Start listening", ImVec2(160, 0))) server.start();
            ImGui::SameLine();
            ImGui::TextDisabled("stopped");
        } else {
            if (ImGui::Button("Stop listening", ImVec2(160, 0))) server.stop();
            ImGui::SameLine();
            ImGui::TextColored(ok_colour, "listening on 127.0.0.1:%u", static_cast<unsigned>(server.listening_port()));
        }

        if (!server.last_error().empty()) ImGui::TextColored(error_colour, "%s", server.last_error().c_str());

        const auto stats = debug_harness::get_stats();
        ImGui::Text("requests: %llu", ull(stats.request_count));
        if (!stats.last_request.empty())
            ImGui::Text("last: %s  (%.2f ms)", stats.last_request.c_str(), stats.last_latency_ms);

        ImGui::TextDisabled("%s  base 0x%llX", debug_harness::live::module_name().c_str(),
                            ull(debug_harness::live::module_base()));
    }

    void draw_writes(ui::write_log& writes) {
        bool armed = writes.armed();
        if (ImGui::Checkbox("Arm writes (auto-disarms after 5 min)", &armed)) writes.set_armed(armed);

        if (armed) {
            ImGui::SameLine();
            ImGui::TextColored(ImVec4(1.f, 0.7f, 0.2f, 1.f), "ARMED  %us left", writes.seconds_left());
        }
        ImGui::TextDisabled("POST /write returns 403 while disarmed.");
        if (!writes.last_error().empty()) ImGui::TextColored(error_colour, "%s", writes.last_error().c_str());

        const auto log = writes.entries();
        if (log.empty() ||
            !ImGui::BeginTable("writes", 5, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY,
                               ImVec2(0, 140)))
            return;

        ImGui::TableSetupColumn("address");
        ImGui::TableSetupColumn("old");
        ImGui::TableSetupColumn("new");
        ImGui::TableSetupColumn("src");
        ImGui::TableSetupColumn("");
        ImGui::TableHeadersRow();

        for (size_t i = 0; i < log.size(); ++i) {
            const auto& record = log[i];
            ImGui::TableNextRow();
            ImGui::PushID(static_cast<int>(i));

            ImGui::TableNextColumn();
            ImGui::Text("0x%llX", ull(record.address));

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(ui::hex_bytes(record.old_bytes).c_str());

            ImGui::TableNextColumn();
            ImGui::TextUnformatted(ui::hex_bytes(record.new_bytes).c_str());

            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", record.source.c_str());

            ImGui::TableNextColumn();
            if (record.reverted)
                ImGui::TextDisabled("reverted");
            else if (ImGui::SmallButton("Revert"))
                writes.revert(i);
            ImGui::PopID();
        }
        ImGui::EndTable();
    }

    void draw_roots(ui::inspector& inspector) {
        if (!ImGui::BeginTable("roots", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg)) return;
        ImGui::TableSetupColumn("root");
        ImGui::TableSetupColumn("value");
        ImGui::TableSetupColumn("note");
        ImGui::TableHeadersRow();

        for (const auto& root : debug_harness::live::roots()) {
            ImGui::TableNextRow();
            ImGui::TableNextColumn();
            ImGui::PushID(root.name.c_str());
            const std::string expression = "@" + root.name;
            ImGui::BeginDisabled(!root.valid);
            if (ImGui::SmallButton(expression.c_str())) inspector.open(expression);
            ImGui::EndDisabled();
            if (root.valid && ImGui::IsItemHovered()) ImGui::SetTooltip("Open in the structure inspector");
            ImGui::PopID();

            ImGui::TableNextColumn();
            if (root.valid)
                ImGui::Text("0x%llX", ull(root.value));
            else
                ImGui::TextColored(error_colour, "invalid");

            ImGui::TableNextColumn();
            ImGui::TextDisabled("%s", root.note.c_str());
        }
        ImGui::EndTable();
    }

    void draw_evaluate(ui::session& session) {
        auto& evaluator = session.evaluator;
        ImGui::SetNextItemWidth(-120);
        const bool submitted = ImGui::InputText("##expr", evaluator.input.data, evaluator.input.capacity,
                                                ImGuiInputTextFlags_EnterReturnsTrue);
        ImGui::SameLine();
        const bool clicked = ImGui::Button("Evaluate", ImVec2(-1, 0));
        if (submitted || clicked) evaluator.evaluate();
        if (evaluator.has_result()) draw_evaluation(evaluator.last_result());

        if (ImGui::SmallButton("Pin as watch")) session.pin_evaluator_as_watch();
        ImGui::SameLine();
        if (ImGui::SmallButton("Open in inspector")) session.open_evaluator_in_inspector();
    }

    void draw_watches(ui::watches& watches) {
        for (size_t i = 0; i < watches.size();) {
            ImGui::PushID(static_cast<int>(i));

            const auto result = watches.evaluate(i);
            if (result.ok)
                ImGui::Text("0x%llX", ull(result.address));
            else
                ImGui::TextColored(error_colour, "%s", result.error.c_str());

            ImGui::SameLine();
            ImGui::TextDisabled("%s", watches.expressions()[i].c_str());
            ImGui::SameLine();

            const bool removed = ImGui::SmallButton("x") && watches.remove(i);
            ImGui::PopID();
            if (!removed) ++i;
        }
    }
}

namespace debug_harness::panel {

    ui::session& session() {
        static ui::session instance;
        return instance;
    }

    void add_section(const std::string& name, std::function<void()> draw, bool default_open) {
        session().add_section(name, std::move(draw), default_open);
    }

    void remove_section(const std::string& name) {
        session().remove_section(name);
    }

    void draw_contents() {
        // No model.tick() here: draw_inspector ticks after its controls, so a Refresh
        // click or span change shows this frame, and a collapsed inspector reads nothing.
        auto& model = session();

        if (ImGui::CollapsingHeader("Server", ImGuiTreeNodeFlags_DefaultOpen)) draw_server(model.server);
        if (ImGui::CollapsingHeader("Writes")) draw_writes(model.writes);
        if (ImGui::CollapsingHeader("Roots", ImGuiTreeNodeFlags_DefaultOpen)) draw_roots(model.inspector);
        if (ImGui::CollapsingHeader("Evaluate", ImGuiTreeNodeFlags_DefaultOpen)) draw_evaluate(model);
        if (ImGui::CollapsingHeader("Structure inspector", ImGuiTreeNodeFlags_DefaultOpen))
            draw_inspector(model.inspector);
        if (!model.watches.empty() && ImGui::CollapsingHeader("Watches", ImGuiTreeNodeFlags_DefaultOpen))
            draw_watches(model.watches);

        // Host sections. Iterate over a copy: a callback may add or remove sections.
        const std::vector<ui::section> sections = model.sections();
        for (const auto& section : sections) {
            if (!section.draw) continue;
            ImGui::PushID(section.name.c_str());
            if (ImGui::CollapsingHeader(section.name.c_str(), section.default_open ? ImGuiTreeNodeFlags_DefaultOpen : 0))
                section.draw();
            ImGui::PopID();
        }
    }

    void draw_window(bool* open, const char* title) {
        ImGui::SetNextWindowSize(ImVec2(680, 620), ImGuiCond_FirstUseEver);
        if (!ImGui::Begin(title ? title : "Debug Harness", open)) {
            ImGui::End();
            return;
        }
        draw_contents();
        ImGui::End();
    }
}
