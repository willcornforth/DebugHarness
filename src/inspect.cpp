#include "debug_harness/inspect.hpp"

#include <algorithm>
#include <cstring>
#include <format>
#include <iterator>

namespace debug_harness::inspect {

    namespace {

        std::string hex_literal(uint64_t value) {
            return std::format("0x{:X}", value);
        }

        // Round the requested span to something safe_read will accept and the row
        // layout can represent: whole qwords, at least one, at most max_span.
        size_t clamp_span(size_t size) {
            if (size > max_span) size = max_span;
            size &= ~static_cast<size_t>(7);
            return size == 0 ? 8 : size;
        }
    }

    void refresh(uint64_t base, size_t requested_size, snapshot& snapshot, uint64_t now_ms, bool reclassify) {
        const size_t size = clamp_span(requested_size == 0 ? default_span : requested_size);
        const size_t row_count = size / 8;

        const bool same_span = snapshot.sample_count > 0 && snapshot.base == base && snapshot.size == size &&
                              snapshot.rows.size() == row_count;

        std::vector<uint8_t> bytes(size, 0);
        std::vector<bool> row_readable(row_count, false);

        // Fast path: one guarded read for the whole span. The slow path only runs
        // when that fails, which means the span leaves committed memory somewhere --
        // and then finding out exactly where is the point.
        const bool whole = debug_harness::mem::safe_read(base, bytes.data(), size);
        if (whole) {
            row_readable.assign(row_count, true);
        } else {
            for (size_t i = 0; i < row_count; ++i) {
                uint8_t* const row = bytes.data() + i * 8;
                if (debug_harness::mem::safe_read(base + i * 8, row, 8))
                    row_readable[i] = true;
                else
                    std::memset(row, 0, 8);
            }
        }

        std::vector<row> rows(row_count);
        size_t readable_rows = 0;

        for (size_t i = 0; i < row_count; ++i) {
            row& row = rows[i];
            row.offset = static_cast<uint64_t>(i) * 8;
            row.address = base + row.offset;
            row.readable = row_readable[i];
            std::memcpy(&row.value, bytes.data() + i * 8, sizeof(row.value));

            if (row.readable)
                ++readable_rows;
            else {
                // Free to state, so it is not deferred like the rest.
                row.classified = true;
                row.kind = debug_harness::mem::kind::garbage;
                row.kind_text = "unreadable";
            }

            if (!same_span) continue;

            const debug_harness::inspect::row& previous = snapshot.rows[i];
            row.change_count = previous.change_count;
            row.changed_at_ms = previous.changed_at_ms;

            // A row flipping between readable and not is a change too: that is what a
            // freed object looks like from here.
            const bool changed = previous.value != row.value || previous.readable != row.readable;
            if (changed) {
                row.change_count = previous.change_count + 1;
                row.changed_at_ms = now_ms;
            } else if (row.readable && previous.classified && !reclassify) {
                // Same bits, same meaning: carrying this forward is what keeps a
                // 4 Hz refresh from re-probing every pointer four times a second.
                row.classified = true;
                row.kind = previous.kind;
                row.kind_text = previous.kind_text;
                row.vtable_slots = previous.vtable_slots;
            }
        }

        const uint64_t sample_count = same_span ? snapshot.sample_count + 1 : 1;

        snapshot.base = base;
        snapshot.size = size;
        snapshot.bytes = std::move(bytes);
        snapshot.rows = std::move(rows);
        snapshot.whole_span_readable = whole;
        snapshot.readable_rows = readable_rows;
        snapshot.sampled_at_ms = now_ms;
        snapshot.sample_count = sample_count;
    }

    void classify(snapshot& snapshot, size_t row_index) {
        if (row_index >= snapshot.rows.size()) return;

        row& row = snapshot.rows[row_index];
        if (row.classified) return;

        const auto classification = debug_harness::mem::classify(row.value);
        row.kind = classification.kind;
        row.kind_text = classification.text;
        row.vtable_slots = classification.vtable_slots;
        row.classified = true;
    }

    void classify_all(snapshot& snapshot) {
        for (size_t i = 0; i < snapshot.rows.size(); ++i)
            classify(snapshot, i);
    }

    void reset_changes(snapshot& snapshot) {
        for (auto& row : snapshot.rows) {
            row.change_count = 0;
            row.changed_at_ms = 0;
        }
    }

    std::vector<hex_line> hex_lines(const snapshot& snapshot) {
        std::vector<hex_line> lines;
        if (snapshot.size == 0) return lines;

        for (size_t start = 0; start < snapshot.size; start += 16) {
            hex_line line;
            line.offset = static_cast<uint64_t>(start);
            line.address = snapshot.base + line.offset;

            for (size_t column = 0; column < 16; ++column) {
                const size_t index = start + column;
                if (column) line.hex += ' ';

                if (index >= snapshot.size) {
                    line.hex += "  ";
                    line.ascii += ' ';
                    continue;
                }

                if (!snapshot.rows[index / 8].readable) {
                    line.hex += "??";
                    line.ascii += '?';
                    continue;
                }

                std::format_to(std::back_inserter(line.hex), "{:02X}", snapshot.bytes[index]);

                const auto byte = snapshot.bytes[index];
                line.ascii += (byte >= 0x20 && byte < 0x7F) ? static_cast<char>(byte) : '.';
            }

            lines.push_back(line);
        }

        return lines;
    }

    std::string append_follow(const std::string& expression, uint64_t offset) {
        if (expression.empty()) return "";
        if (offset == 0) return expression + "[]";
        return expression + "[+" + hex_literal(offset) + "]";
    }

    std::string append_add(const std::string& expression, int64_t delta) {
        if (expression.empty() || delta < 0) return "";
        if (delta == 0) return expression;
        return expression + "+" + hex_literal(static_cast<uint64_t>(delta));
    }
}
