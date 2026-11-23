#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <functional>
#include <string>
#include <string_view>
#include <vector>

#include "debug_harness/expr.hpp"
#include "debug_harness/inspect.hpp"
#include "debug_harness/mem.hpp"

// ImGui-free view models for the Debug Harness window.
//
// Everything the window *knows* lives here: the expression being evaluated, the
// pinned watches, the structure inspector's navigation history and refresh policy,
// the server's port and last start error, the write log. A renderer -- the optional
// imgui/debug_harness_panel.cpp, or the host's own UI -- only draws these and calls
// their methods in response to clicks. Nothing in this header names an ImGui type,
// so a consumer without ImGui still compiles it, and the host tests drive it directly.
//
// Threading: every class here is render-thread state. None of them is thread-safe;
// the HTTP server never touches them.
//
// Typical use from a host's own per-frame callback:
//
//     static debug_harness::ui::session session;
//     session.tick(GetTickCount64()); // re-reads the inspector span when due
//     ... draw from session.inspector / session.watches / ...
namespace debug_harness::ui {

    // A fixed, always-terminated char buffer an immediate-mode text field can edit in
    // place (ImGui::InputText and friends want a char* and a capacity, not a std::string).
    template <size_t N> struct text_buffer {
        static_assert(N > 1, "a text buffer needs room for at least one character and the terminator");
        static constexpr size_t capacity = N;

        char data[N] = {};

        text_buffer() = default;
        text_buffer(std::string_view text) { set(text); }

        // Overwrite, truncating to N - 1 characters.
        void set(std::string_view text) {
            const size_t count = text.size() < N - 1 ? text.size() : N - 1;
            for (size_t i = 0; i < count; ++i) data[i] = text[i];
            data[count] = '\0';
        }

        std::string_view view() const { return std::string_view(data); }
        std::string str() const { return std::string(data); }
    };

    using expression_buffer = text_buffer<256>;

    // How long a changed row stays highlighted. Long enough to catch out of the corner
    // of an eye while looking at the host, short enough that a field updating every
    // frame still reads as "constantly changing" rather than "permanently lit".
    constexpr uint64_t change_fade_ms = 1200;

    // 1 for a row that changed this instant, falling linearly to 0 at change_fade_ms;
    // 0 for a row never seen to change.
    float change_intensity(uint64_t changed_at_ms, uint64_t now_ms);

    // The most recent changed_at_ms of the (up to two) qword rows a 16-byte hex line
    // starting at `offset` covers. 0 when neither changed.
    uint64_t newest_change_in_line(const inspect::snapshot& snapshot, uint64_t offset);

    // "48 8B C4" without separators: "488BC4". Used by the write log.
    std::string hex_bytes(const std::vector<uint8_t>& bytes);

    // Reinterpret 32 bits as an IEEE float (the inspector's f32 lo/hi column).
    float as_float(uint32_t bits);

    // Whether the inspector offers to follow a row's value as a pointer. Only
    // meaningful once the row is classified.
    bool is_followable(const inspect::row& row);

    // Short human label for a mem::kind ("code", "vtable", ...).
    const char* kind_name(mem::kind kind);

    // Where an address lives, without guessing: a module name, "mapped", "image" or
    // "private" -- never "heap", which the data cannot support.
    std::string region_origin(const mem::region_info& region);

    // --- evaluate -------------------------------------------------------------

    class evaluator {
    public:
        expression_buffer input{"@base"};

        // Evaluate `input` against the live process (debug_harness::live::env()).
        void evaluate();
        // Evaluate `input` against a caller-supplied environment (tests, other hosts).
        void evaluate(const expr::env& env);

        bool has_result() const { return has_result_; }
        const expr::result& last_result() const { return result_; }
        void clear() {
            has_result_ = false;
            result_ = {};
        }

    private:
        expr::result result_;
        bool has_result_ = false;
    };

    // --- watches --------------------------------------------------------------

    class watches {
    public:
        void add(std::string expression);
        // Out-of-range indices are ignored. Returns whether something was removed.
        bool remove(size_t index);
        void clear() { expressions_.clear(); }

        size_t size() const { return expressions_.size(); }
        bool empty() const { return expressions_.empty(); }
        const std::vector<std::string>& expressions() const { return expressions_; }

        // Watches are re-evaluated every time they are drawn; that is the point of them.
        expr::result evaluate(size_t index) const;
        expr::result evaluate(size_t index, const expr::env& env) const;

    private:
        std::vector<std::string> expressions_;
    };

    // --- structure inspector --------------------------------------------------

    // One stop in the navigation history.
    //
    // Paging is a signed delta from the anchor rather than a mutated address, so the
    // path expression collapses -- ten pages forward reads "@x+0xA00", not ten
    // concatenated addends -- and paging back to the anchor restores the clean
    // expression instead of losing it.
    struct nav_entry {
        std::string expression; // anchor expression; "" when reached by literal
        uint64_t anchor = 0;
        int64_t delta = 0;

        uint64_t address() const { return anchor + static_cast<uint64_t>(delta); }

        // The pastable expression for the current view, or "" when there is none.
        // append_add refuses a negative delta: the grammar has no subtraction, so
        // anything before the anchor has no expressible form.
        std::string path() const { return inspect::append_add(expression, delta); }
    };

    constexpr std::array<size_t, 7> span_choices = {0x40, 0x80, 0x100, 0x200, 0x400, 0x800, 0x1000};
    constexpr std::array<const char*, 7> span_labels = {"0x40", "0x80", "0x100", "0x200", "0x400", "0x800", "0x1000"};
    static_assert(span_choices.back() <= inspect::max_span, "every span choice must fit one safe_read");
    constexpr int default_span_index = 2; // 0x100

    enum class refresh_mode { every_frame, four_hz, manual };
    constexpr std::array<const char*, 3> refresh_mode_labels = {"every frame", "4 Hz", "manual"};
    constexpr uint64_t four_hz_interval_ms = 250;

    constexpr size_t history_capacity = 64;

    class inspector {
    public:
        expression_buffer input{"@base"};

        // --- navigation ---

        // Evaluate `expression` and, on success, push it as a new history entry.
        // On failure the history is untouched and error() says why.
        bool go(const std::string& expression);
        bool go(const std::string& expression, const expr::env& env);
        // go(input).
        bool go();
        // Set `input` to `expression`, then go to it (the Roots / "Open in inspector" buttons).
        bool open(const std::string& expression);

        // Push an already-resolved address. `expression` may be "" for a bare address.
        void navigate(const std::string& expression, uint64_t address);

        bool can_go_back() const { return history_.size() >= 2; }
        void back();

        // Move the view by `bytes` from the current anchor. Refused (false) only when it
        // would take the view below address 0. The test is on the resulting delta, not on
        // `bytes`: paging back from +0x200 to +0x100 is still forward of the anchor.
        bool page(int64_t bytes);
        bool page_forward() { return page(static_cast<int64_t>(span())); }
        bool page_back() { return page(-static_cast<int64_t>(span())); }
        bool at_anchor() const { return history_.empty() || history_.back().delta == 0; }
        void to_anchor();

        // Follow row `row_index`'s value as a pointer: navigates to it with the
        // expression path()[+offset]. Invalidates current(), snapshot() and any row
        // reference, so a renderer calls this *after* it has finished drawing the table.
        bool follow(size_t row_index);

        bool has_current() const { return !history_.empty(); }
        // Precondition: has_current().
        const nav_entry& current() const { return history_.back(); }
        const std::vector<nav_entry>& history() const { return history_; }

        // The expression that reaches the current view, falling back to "va:0x..." when
        // the view has no expressible form. "" when there is no current view.
        std::string path() const;

        const std::string& error() const { return error_; }

        // --- span and refresh policy ---

        int span_index() const { return span_index_; }
        // Clamped into span_choices; forces a refresh when it changes.
        void set_span_index(int index);
        size_t span() const { return span_choices[static_cast<size_t>(span_index_)]; }

        refresh_mode mode() const { return mode_; }
        void set_mode(refresh_mode mode) { mode_ = mode; }

        // Re-read on the next tick. `reclassify` also forgets every classification: an
        // explicit Refresh is the way to say a pointer whose value did not change may now
        // point at reused memory.
        void request_refresh(bool reclassify = false);

        // Re-read the span if due (forced, every-frame, or 4 Hz and >= 250 ms since the
        // last read) and rebuild the hex-line cache if the hex view is on and the
        // snapshot moved. Returns whether a read happened. Call once per frame.
        bool tick(uint64_t now_ms);

        // The now_ms of the most recent tick, for fading change marks.
        uint64_t now_ms() const { return now_ms_; }
        uint64_t last_refresh_ms() const { return last_refresh_ms_; }

        // --- view options ---

        bool hex_view() const { return hex_view_; }
        void set_hex_view(bool on);
        bool changed_only() const { return changed_only_; }
        void set_changed_only(bool on) { changed_only_ = on; }

        // Forget every recorded change without re-reading: clear, act in the host, look again.
        void reset_change_marks();

        // --- what to draw ---

        const inspect::snapshot& snapshot() const { return snapshot_; }

        // Indices into snapshot().rows that pass the changed-only filter. Rebuilt on each
        // call into a reused buffer so the filter pass does not allocate per frame.
        const std::vector<size_t>& visible_rows();

        // Classify one row (snapshot index). Renderers call this only for the rows they
        // actually draw -- classification probes up to 256 vtable slots per row, so a
        // full 0x1000 span on the render thread is a visible stall.
        void classify_row(size_t row_index);
        // Classify visible_rows()[first .. last), e.g. a list clipper's display range.
        void classify_visible(size_t first, size_t last);

        // Cached inspect::hex_lines(snapshot()); valid after tick() while hex_view() is on.
        const std::vector<inspect::hex_line>& hex_lines() const { return hex_lines_; }

    private:
        void reset_view();

        std::vector<nav_entry> history_;
        inspect::snapshot snapshot_;
        std::string error_;

        int span_index_ = default_span_index;
        refresh_mode mode_ = refresh_mode::four_hz;
        bool force_refresh_ = false;
        bool force_reclassify_ = false;
        uint64_t last_refresh_ms_ = 0;
        uint64_t now_ms_ = 0;

        bool hex_view_ = false;
        bool changed_only_ = false;

        std::vector<inspect::hex_line> hex_lines_;
        uint64_t hex_lines_sample_ = 0;
        uint64_t hex_lines_base_ = 0;
        size_t hex_lines_size_ = 0;

        std::vector<size_t> visible_rows_;
    };

    // --- server ---------------------------------------------------------------

    class server_control {
    public:
        server_control();

        // The port start() will use. Clamped to 1024..65535.
        int port() const { return port_; }
        void set_port(int port);

        // Start the HTTP listener on port(). On failure last_error() holds the reason,
        // which is also forwarded to the host log.
        bool start();
        void stop();
        bool running() const;
        // The port actually bound while running; 0 when stopped.
        unsigned short listening_port() const;

        const std::string& last_error() const { return last_error_; }
        void clear_error() { last_error_.clear(); }

    private:
        int port_;
        std::string last_error_;
    };

    // --- writes ---------------------------------------------------------------

    constexpr unsigned int default_arm_seconds = 300;

    class write_log {
    public:
        // Arming is only reachable from the in-process UI, never over HTTP.
        bool armed() const;
        void set_armed(bool armed, unsigned int auto_disarm_seconds = default_arm_seconds);
        unsigned int seconds_left() const;

        // A snapshot copy of mem::undo_log().
        std::vector<mem::write_record> entries() const;

        // Restore one write. On failure last_error() says why (also forwarded to the host log).
        bool revert(size_t undo_index);
        const std::string& last_error() const { return last_error_; }

    private:
        std::string last_error_;
    };

    // --- host sections --------------------------------------------------------

    // A host-supplied block appended to the panel, e.g. a game-specific script console.
    // `draw` runs inside the renderer's frame (for the ImGui panel: inside the window,
    // under a collapsing header named `name`).
    struct section {
        std::string name;
        std::function<void()> draw;
        bool default_open = false;
    };

    // --- session --------------------------------------------------------------

    // Everything the Debug Harness window holds, in one object a renderer owns.
    class session {
    public:
        ui::evaluator evaluator;
        ui::watches watches;
        ui::inspector inspector;
        ui::server_control server;
        ui::write_log writes;

        // Per-frame work that does not depend on what is drawn: the inspector re-read.
        void tick(uint64_t now_ms) { inspector.tick(now_ms); }

        // "Pin as watch": the evaluator's current expression becomes a watch.
        void pin_evaluator_as_watch() { watches.add(evaluator.input.str()); }
        // "Open in inspector": the evaluator's current expression goes to the inspector.
        bool open_evaluator_in_inspector() { return inspector.open(evaluator.input.str()); }

        // Re-adding a name replaces that section's draw callback in place.
        void add_section(std::string name, std::function<void()> draw, bool default_open = false);
        bool remove_section(const std::string& name);
        const std::vector<section>& sections() const { return sections_; }

    private:
        std::vector<section> sections_;
    };
}
