#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "debug_harness/mem.hpp"

// The structure inspector's model: a re-readable window onto a span of memory,
// with per-qword classification and change tracking.
//
// This is the x64dbg dump pane reduced to the one job that matters here --
// working out what the fields of an unknown struct are. Two things do that work:
// the classification column proposes what each qword *is*, and the change counter
// records which qwords move while the host runs, which is how a health float or a
// state enum gives itself away.
//
// No ImGui and no host headers: a renderer (e.g. the optional ImGui panel) draws what
// this produces, and the host tests exercise it directly.
namespace debug_harness::inspect {

    // A read has to fit one safe_read, and safe_read caps at max_read_bytes.
    constexpr size_t max_span = debug_harness::mem::max_read_bytes;
    constexpr size_t default_span = 0x100;

    struct row {
        uint64_t offset = 0; // from the span base
        uint64_t address = 0;
        uint64_t value = 0;
        bool readable = false;

        // Classification is lazy -- see Classify below. Only read these when
        // `classified` is true.
        bool classified = false;
        debug_harness::mem::kind kind = debug_harness::mem::kind::garbage;
        std::string kind_text;
        uint64_t vtable_slots = 0;

        // Change tracking, reset when the span moves or reset_changes is called.
        uint64_t change_count = 0;
        uint64_t changed_at_ms = 0; // 0 when never seen to change
    };

    struct snapshot {
        uint64_t base = 0;
        size_t size = 0;
        std::vector<uint8_t> bytes; // size bytes; zero where unreadable
        std::vector<row> rows;      // size/8 entries
        bool whole_span_readable = false;
        size_t readable_rows = 0;
        uint64_t sampled_at_ms = 0;
        uint64_t sample_count = 0;
    };

    // Re-read the span, preserving change history when `base` and `size` are
    // unchanged and discarding it when they are not.
    //
    // The whole span is attempted in one safe_read first. That is the common case and
    // costs one pass; only if it fails does this fall back to reading qword by qword,
    // so a span running off the end of a committed region still shows the rows that
    // are there instead of nothing at all.
    //
    // Classification is NOT performed here, and a row whose value has not changed
    // keeps the classification it already had. `reclassify` forces every row back to
    // unclassified, for when the caller suspects the memory a pointer refers to has
    // been reused underneath an unchanged pointer value.
    void refresh(uint64_t base, size_t size, snapshot& snapshot, uint64_t now_ms, bool reclassify = false);

    // Classify one row, if it is not classified already.
    //
    // Kept out of Refresh and off by default because it is by far the most expensive
    // thing here: debug_harness::mem::classify probes up to 256 vtable slots, each costing two
    // VirtualQuery calls, so classifying a full span can run to six figures of
    // syscalls. On the render thread that is a visible stall. Callers classify only
    // the rows they are about to draw, and Refresh carries the answers forward, so
    // steady-state cost is zero.
    void classify(snapshot& snapshot, size_t row_index);

    // Classify every row. For callers not on a frame budget.
    void classify_all(snapshot& snapshot);

    // Forget every recorded change without re-reading. Use before an in-host action
    // to see only what that action touched.
    void reset_changes(snapshot& snapshot);

    // 16 bytes per line, with the printable gutter. Unreadable bytes render as "??"
    // in the hex column and '?' in the gutter, so a partially mapped span is obvious.
    struct hex_line {
        uint64_t offset = 0;
        uint64_t address = 0;
        std::string hex;   // "48 8B C4 ?? ..."
        std::string ascii; // 16 chars
    };
    std::vector<hex_line> hex_lines(const snapshot& snapshot);

    // --- expression tracking -------------------------------------------------
    //
    // Following a pointer in the inspector is only half the answer; the other half is
    // the expression that reaches it, which is what gets pasted into the host's offset table
    // or a /chain call. These build it as the user navigates.

    // "@x" + 0x130 -> "@x[+0x130]"; offset 0 -> "@x[]". Empty in, empty out: an
    // address typed as a bare number has no expression to extend.
    std::string append_follow(const std::string& expression, uint64_t offset);

    // "@x" + 0x40 -> "@x+0x40". The grammar has no subtraction, so a negative delta
    // yields "" and the caller falls back to va:.
    std::string append_add(const std::string& expression, int64_t delta);
}
