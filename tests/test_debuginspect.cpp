#include "harness.hpp"

#include "debug_harness/expr.hpp"
#include "debug_harness/inspect.hpp"

#include <Windows.h>

#include <cstring>
#include <map>
#include <string>

namespace {

    // A committed page we can scribble on, so change tracking has something to see.
    struct scratch_page {
        uint8_t* address = nullptr;
        scratch_page() {
            address = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE));
            if (address) std::memset(address, 0, 0x1000);
        }
        ~scratch_page() {
            if (address) VirtualFree(address, 0, MEM_RELEASE);
        }
        uint64_t addr() const { return reinterpret_cast<uint64_t>(address); }
    };

    // Two pages reserved, only the first committed: a span crossing the boundary is
    // exactly the "struct runs off the end of the allocation" case.
    struct half_committed_pair {
        uint8_t* address = nullptr;
        half_committed_pair() {
            address = static_cast<uint8_t*>(VirtualAlloc(nullptr, 0x2000, MEM_RESERVE, PAGE_NOACCESS));
            if (address) {
                VirtualAlloc(address, 0x1000, MEM_COMMIT, PAGE_READWRITE);
                std::memset(address, 0xAB, 0x1000);
            }
        }
        ~half_committed_pair() {
            if (address) VirtualFree(address, 0, MEM_RELEASE);
        }
        uint64_t addr() const { return reinterpret_cast<uint64_t>(address); }
    };
}

TEST(refresh_reads_a_committed_span_whole) {
    scratch_page page;
    CHECK(page.address != nullptr);
    for (int i = 0; i < 8; ++i)
        reinterpret_cast<uint64_t*>(page.address)[i] = 0x1000ull + i;

    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x40, snapshot, 1000);

    CHECK(snapshot.whole_span_readable);
    CHECK_EQ(snapshot.base, page.addr());
    CHECK_EQ(snapshot.size, static_cast<size_t>(0x40));
    CHECK_EQ(snapshot.rows.size(), static_cast<size_t>(8));
    CHECK_EQ(snapshot.readable_rows, static_cast<size_t>(8));
    CHECK_EQ(snapshot.sample_count, 1ull);

    for (size_t i = 0; i < 8; ++i) {
        CHECK(snapshot.rows[i].readable);
        CHECK_EQ(snapshot.rows[i].offset, static_cast<uint64_t>(i * 8));
        CHECK_EQ(snapshot.rows[i].address, page.addr() + i * 8);
        CHECK_EQ(snapshot.rows[i].value, 0x1000ull + i);
        CHECK_EQ(snapshot.rows[i].change_count, 0ull);
    }
}

TEST(refresh_clamps_the_span_to_whole_qwords) {
    scratch_page page;
    debug_harness::inspect::snapshot snapshot;

    debug_harness::inspect::refresh(page.addr(), 0x41, snapshot, 0);
    CHECK_EQ(snapshot.size, static_cast<size_t>(0x40));

    debug_harness::inspect::refresh(page.addr(), 3, snapshot, 0);
    CHECK_EQ(snapshot.size, static_cast<size_t>(8));
}

TEST(refresh_defaults_an_unspecified_span) {
    scratch_page page;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0, snapshot, 0);
    CHECK_EQ(snapshot.size, debug_harness::inspect::default_span);
}

TEST(refresh_never_exceeds_the_safe_read_ceiling) {
    scratch_page page;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x10000, snapshot, 0);
    CHECK_EQ(snapshot.size, debug_harness::inspect::max_span);
}

TEST(refresh_counts_changes_per_row) {
    scratch_page page;
    auto* const qwords = reinterpret_cast<uint64_t*>(page.address);
    qwords[0] = 1;
    qwords[1] = 2;

    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 1000);
    CHECK_EQ(snapshot.rows[0].change_count, 0ull);

    qwords[1] = 99;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 2000);

    CHECK_EQ(snapshot.sample_count, 2ull);
    CHECK_EQ(snapshot.rows[0].change_count, 0ull);
    CHECK_EQ(snapshot.rows[0].changed_at_ms, 0ull);
    CHECK_EQ(snapshot.rows[1].change_count, 1ull);
    CHECK_EQ(snapshot.rows[1].changed_at_ms, 2000ull);
    CHECK_EQ(snapshot.rows[1].value, 99ull);

    qwords[1] = 100;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 3000);
    CHECK_EQ(snapshot.rows[1].change_count, 2ull);
    CHECK_EQ(snapshot.rows[1].changed_at_ms, 3000ull);
}

TEST(refresh_discards_change_history_when_the_span_moves) {
    scratch_page page;
    auto* const qwords = reinterpret_cast<uint64_t*>(page.address);

    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 1000);
    qwords[1] = 7;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 2000);
    CHECK_EQ(snapshot.rows[1].change_count, 1ull);

    debug_harness::inspect::refresh(page.addr() + 0x100, 0x20, snapshot, 3000);
    CHECK_EQ(snapshot.sample_count, 1ull);
    CHECK_EQ(snapshot.rows[1].change_count, 0ull);
}

TEST(refresh_discards_change_history_when_the_span_resizes) {
    scratch_page page;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 1000);
    debug_harness::inspect::refresh(page.addr(), 0x40, snapshot, 2000);
    CHECK_EQ(snapshot.sample_count, 1ull);
    CHECK_EQ(snapshot.rows.size(), static_cast<size_t>(8));
}

TEST(reset_changes_clears_the_counters_without_rereading) {
    scratch_page page;
    auto* const qwords = reinterpret_cast<uint64_t*>(page.address);

    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 1000);
    qwords[0] = 5;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 2000);
    CHECK_EQ(snapshot.rows[0].change_count, 1ull);

    debug_harness::inspect::reset_changes(snapshot);
    CHECK_EQ(snapshot.rows[0].change_count, 0ull);
    CHECK_EQ(snapshot.rows[0].changed_at_ms, 0ull);
    CHECK_EQ(snapshot.rows[0].value, 5ull); // the data itself is untouched
}

TEST(refresh_falls_back_to_per_row_reads_at_a_region_boundary) {
    half_committed_pair pair;
    CHECK(pair.address != nullptr);

    // Sixteen readable rows, then sixteen that are not.
    const uint64_t start = pair.addr() + 0x1000 - 0x80;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(start, 0x100, snapshot, 0);

    CHECK(!snapshot.whole_span_readable);
    CHECK_EQ(snapshot.rows.size(), static_cast<size_t>(32));
    CHECK_EQ(snapshot.readable_rows, static_cast<size_t>(16));

    for (size_t i = 0; i < 16; ++i) {
        CHECK(snapshot.rows[i].readable);
        CHECK_EQ(snapshot.rows[i].value, 0xABABABABABABABABull);
    }
    for (size_t i = 16; i < 32; ++i) {
        CHECK(!snapshot.rows[i].readable);
        CHECK_EQ(snapshot.rows[i].value, 0ull);
        CHECK_STR_EQ(snapshot.rows[i].kind_text, "unreadable");
    }
}

TEST(refresh_leaves_readable_rows_unclassified) {
    scratch_page page;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 0);

    // Classification probes memory and is the expensive part; Refresh must not do it.
    for (const auto& row : snapshot.rows)
        CHECK(!row.classified);
}

TEST(classify_populates_one_row_and_leaves_the_rest_alone) {
    scratch_page page;
    reinterpret_cast<uint64_t*>(page.address)[1] = 0x2A;

    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 0);
    debug_harness::inspect::classify(snapshot, 1);

    CHECK(snapshot.rows[1].classified);
    CHECK(snapshot.rows[1].kind == debug_harness::mem::kind::small_int);
    CHECK(snapshot.rows[1].kind_text.find("2A") != std::string::npos);
    CHECK(!snapshot.rows[0].classified);
}

TEST(classify_out_of_range_is_a_no_op) {
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::classify(snapshot, 0); // empty snapshot
    debug_harness::inspect::classify(snapshot, 999999);
    CHECK(snapshot.rows.empty());
}

TEST(classify_all_classifies_every_row) {
    scratch_page page;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 0);
    debug_harness::inspect::classify_all(snapshot);

    for (const auto& row : snapshot.rows)
        CHECK(row.classified);
}

TEST(refresh_carries_a_classification_forward_while_the_value_holds) {
    scratch_page page;
    auto* const qwords = reinterpret_cast<uint64_t*>(page.address);
    qwords[0] = 0x2A;

    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 1000);
    debug_harness::inspect::classify_all(snapshot);
    const std::string before = snapshot.rows[0].kind_text;

    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 2000);
    CHECK(snapshot.rows[0].classified);
    CHECK_STR_EQ(snapshot.rows[0].kind_text, before);
}

TEST(refresh_drops_a_classification_when_the_value_changes) {
    scratch_page page;
    auto* const qwords = reinterpret_cast<uint64_t*>(page.address);
    qwords[0] = 0x2A;

    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 1000);
    debug_harness::inspect::classify_all(snapshot);

    qwords[0] = 0x2B;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 2000);
    CHECK(!snapshot.rows[0].classified);
}

TEST(refresh_with_reclassify_drops_every_classification) {
    scratch_page page;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 1000);
    debug_harness::inspect::classify_all(snapshot);

    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 2000, /*reclassify=*/true);
    for (const auto& row : snapshot.rows) {
        if (row.readable) CHECK(!row.classified);
    }
}

TEST(an_unreadable_row_is_classified_without_probing) {
    half_committed_pair pair;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(pair.addr() + 0x1000 - 0x10, 0x20, snapshot, 0);

    // Rows past the boundary need no memory access to describe, so Refresh does them.
    CHECK(snapshot.rows[2].classified);
    CHECK_STR_EQ(snapshot.rows[2].kind_text, "unreadable");
}

TEST(refresh_treats_a_row_becoming_unreadable_as_a_change) {
    scratch_page page;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 1000);
    CHECK(snapshot.rows[0].readable);

    DWORD previous = 0;
    CHECK(VirtualProtect(page.address, 0x1000, PAGE_NOACCESS, &previous) != 0);
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 2000);
    VirtualProtect(page.address, 0x1000, previous, &previous);

    CHECK(!snapshot.rows[0].readable);
    CHECK_EQ(snapshot.rows[0].change_count, 1ull);
    CHECK_EQ(snapshot.rows[0].changed_at_ms, 2000ull);
}

TEST(hex_lines_renders_sixteen_bytes_per_line_with_a_gutter) {
    scratch_page page;
    std::memcpy(page.address, "Hello\x01World!!!!", 16);

    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x20, snapshot, 0);

    const auto lines = debug_harness::inspect::hex_lines(snapshot);
    CHECK_EQ(lines.size(), static_cast<size_t>(2));
    CHECK_EQ(lines[0].offset, 0ull);
    CHECK_EQ(lines[0].address, page.addr());
    CHECK_EQ(lines[1].offset, 0x10ull);
    CHECK_STR_EQ(lines[0].hex, "48 65 6C 6C 6F 01 57 6F 72 6C 64 21 21 21 21 00");
    CHECK_STR_EQ(lines[0].ascii, "Hello.World!!!!.");
}

TEST(hex_lines_marks_unreadable_bytes) {
    half_committed_pair pair;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(pair.addr() + 0x1000 - 0x10, 0x20, snapshot, 0);

    const auto lines = debug_harness::inspect::hex_lines(snapshot);
    CHECK_EQ(lines.size(), static_cast<size_t>(2));
    CHECK_STR_EQ(lines[1].hex, "?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ?? ??");
    CHECK_STR_EQ(lines[1].ascii, "????????????????");
}

TEST(hex_lines_pads_a_trailing_half_line) {
    scratch_page page;
    debug_harness::inspect::snapshot snapshot;
    debug_harness::inspect::refresh(page.addr(), 0x18, snapshot, 0);

    const auto lines = debug_harness::inspect::hex_lines(snapshot);
    CHECK_EQ(lines.size(), static_cast<size_t>(2));
    CHECK_EQ(lines[1].hex.size(), static_cast<size_t>(47));
    CHECK_EQ(lines[1].ascii.size(), static_cast<size_t>(16));
    CHECK_STR_EQ(lines[1].hex.substr(24), "                       ");
}

TEST(append_follow_builds_a_dereference_suffix) {
    CHECK_STR_EQ(debug_harness::inspect::append_follow("@local.character", 0x130), "@local.character[+0x130]");
    CHECK_STR_EQ(debug_harness::inspect::append_follow("@local.character", 0), "@local.character[]");
    CHECK_STR_EQ(debug_harness::inspect::append_follow("", 0x130), "");
}

TEST(append_add_builds_an_offset_suffix_and_refuses_to_go_backwards) {
    CHECK_STR_EQ(debug_harness::inspect::append_add("rva:0x1000", 0x40), "rva:0x1000+0x40");
    CHECK_STR_EQ(debug_harness::inspect::append_add("rva:0x1000", 0), "rva:0x1000");
    CHECK_STR_EQ(debug_harness::inspect::append_add("rva:0x1000", -0x40), "");
    CHECK_STR_EQ(debug_harness::inspect::append_add("", 0x40), "");
}

namespace {
    // The point of the builders is that what they emit can be pasted straight back
    // into /chain, so evaluate it rather than only comparing strings.
    struct stub_env : debug_harness::expr::env {
        std::map<uint64_t, uint64_t> reads;

        uint64_t module_base() const override { return 0x140000000ull; }
        uint64_t preferred_base() const override { return 0x140000000ull; }
        bool root(const std::string& name, uint64_t& out_value, std::string& out_note) const override {
            if (name != "obj") return false;
            out_value = 0x20000000ull;
            out_note = "stub";
            return true;
        }
        bool symbol(const std::string&, uint64_t&) const override { return false; }
        bool read_u64(uint64_t address, uint64_t& out_value, std::string& out_note) const override {
            const auto found = reads.find(address);
            if (found == reads.end()) {
                out_note = "unreadable";
                return false;
            }
            out_value = found->second;
            out_note = "stub read";
            return true;
        }
    };
}

TEST(a_followed_expression_evaluates_back_to_the_followed_address) {
    stub_env env;
    env.reads[0x20000000ull + 0x130] = 0x30000000ull;
    env.reads[0x30000000ull + 0x60] = 0x40000000ull;

    const auto first = debug_harness::inspect::append_follow("@obj", 0x130);
    const auto second = debug_harness::inspect::append_follow(first, 0x60);
    const auto nudged = debug_harness::inspect::append_add(second, 0x3C);
    CHECK_STR_EQ(nudged, "@obj[+0x130][+0x60]+0x3C");

    const auto result = debug_harness::expr::evaluate(nudged, env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x40000000ull + 0x3C);
}

TEST(a_bare_dereference_expression_evaluates) {
    stub_env env;
    env.reads[0x20000000ull] = 0x50000000ull;

    const auto result = debug_harness::expr::evaluate(debug_harness::inspect::append_follow("@obj", 0), env);
    CHECK(result.ok);
    CHECK_EQ(result.address, 0x50000000ull);
}
