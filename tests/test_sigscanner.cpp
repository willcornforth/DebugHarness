#include "harness.hpp"

#include "debug_harness/scan.hpp"

#include <cstdint>
#include <vector>

namespace {
    // Three occurrences of "AA BB", at indices 0, 4 and 8.
    const std::vector<uint8_t> buffer = {0xAA, 0xBB, 0x01, 0x02, 0xAA, 0xBB, 0x03, 0x04, 0xAA, 0xBB, 0x05, 0x06};

    uintptr_t buffer_base() {
        return reinterpret_cast<uintptr_t>(buffer.data());
    }
}

TEST(parse_pattern_accepts_hex_and_wildcards) {
    std::vector<debug_harness::scan::pattern_byte> bytes;
    CHECK(debug_harness::scan::parse_pattern("48 8B ? ?? 0D", bytes));
    CHECK_EQ(bytes.size(), static_cast<size_t>(5));
    CHECK_EQ(bytes[0].value, static_cast<uint8_t>(0x48));
    CHECK(!bytes[0].is_wildcard);
    CHECK(bytes[2].is_wildcard);
    CHECK(bytes[3].is_wildcard);
    CHECK_EQ(bytes[4].value, static_cast<uint8_t>(0x0D));
}

TEST(parse_pattern_rejects_garbage_without_throwing) {
    std::vector<debug_harness::scan::pattern_byte> bytes;
    CHECK(!debug_harness::scan::parse_pattern("48 ZZ", bytes));
    CHECK(!debug_harness::scan::parse_pattern("48 1FF", bytes));
    CHECK(!debug_harness::scan::parse_pattern("", bytes));
    CHECK(!debug_harness::scan::parse_pattern("   ", bytes));
}

TEST(find_pattern_finds_first_match_in_range) {
    const auto hit = debug_harness::scan::find_pattern(buffer_base(), buffer.size(), "AA BB 01");
    CHECK_EQ(hit, buffer_base());
}

TEST(find_pattern_returns_zero_when_absent) {
    CHECK_EQ(debug_harness::scan::find_pattern(buffer_base(), buffer.size(), "DE AD BE EF"), static_cast<uintptr_t>(0));
}

TEST(find_pattern_returns_zero_when_pattern_longer_than_range) {
    CHECK_EQ(debug_harness::scan::find_pattern(buffer_base(), 2, "AA BB 01 02"), static_cast<uintptr_t>(0));
}

TEST(find_all_reports_every_hit_and_the_total) {
    const auto result = debug_harness::scan::find_all(buffer_base(), buffer.size(), "AA BB", 16);
    CHECK(result.pattern_valid);
    CHECK_EQ(result.total_hits, static_cast<size_t>(3));
    CHECK_EQ(result.hits.size(), static_cast<size_t>(3));
    CHECK_EQ(result.hits[0], buffer_base() + 0);
    CHECK_EQ(result.hits[1], buffer_base() + 4);
    CHECK_EQ(result.hits[2], buffer_base() + 8);
}

TEST(find_all_caps_returned_hits_but_still_counts_all) {
    const auto result = debug_harness::scan::find_all(buffer_base(), buffer.size(), "AA BB", 2);
    CHECK_EQ(result.hits.size(), static_cast<size_t>(2));
    CHECK_EQ(result.total_hits, static_cast<size_t>(3));
}

TEST(find_all_flags_an_invalid_pattern) {
    const auto result = debug_harness::scan::find_all(buffer_base(), buffer.size(), "NOPE", 8);
    CHECK(!result.pattern_valid);
    CHECK_EQ(result.total_hits, static_cast<size_t>(0));
    CHECK(result.hits.empty());
}

TEST(find_all_overlapping_matches_are_all_reported) {
    const std::vector<uint8_t> overlapping = {0xAA, 0xAA, 0xAA};
    const auto base = reinterpret_cast<uintptr_t>(overlapping.data());
    const auto result = debug_harness::scan::find_all(base, overlapping.size(), "AA AA", 8);
    CHECK_EQ(result.total_hits, static_cast<size_t>(2));
}

TEST(resolve_rip_relative_decodes_a_call_rel32) {
    // E8 05 00 00 00  == call +5, instruction length 5.
    const std::vector<uint8_t> code = {0xE8, 0x05, 0x00, 0x00, 0x00};
    const auto base = reinterpret_cast<uintptr_t>(code.data());
    CHECK_EQ(debug_harness::scan::resolve_rip_relative(base, 1, 5), base + 5 + 5);
}

TEST(resolve_rip_relative_handles_a_negative_displacement) {
    // E8 FB FF FF FF == call -5.
    const std::vector<uint8_t> code = {0xE8, 0xFB, 0xFF, 0xFF, 0xFF};
    const auto base = reinterpret_cast<uintptr_t>(code.data());
    CHECK_EQ(debug_harness::scan::resolve_rip_relative(base, 1, 5), base + 5 - 5);
}

TEST(module_range_describes_the_test_executable) {
    uintptr_t base = 0;
    size_t size = 0;
    CHECK(debug_harness::scan::module_range(base, size));
    CHECK(base != 0);
    CHECK(size > 0x1000);
}
