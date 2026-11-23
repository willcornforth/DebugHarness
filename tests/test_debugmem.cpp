#include "harness.hpp"

#include "debug_harness/mem.hpp"

#include <Windows.h>

#include <cstring>
#include <string>
#include <vector>

namespace {
    volatile int known_global = 0x11223344;

    // A committed page we can flip to PAGE_NOACCESS / PAGE_GUARD.
    struct scratch_page {
        void* address = nullptr;
        scratch_page() { address = VirtualAlloc(nullptr, 0x1000, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE); }
        ~scratch_page() {
            if (address) VirtualFree(address, 0, MEM_RELEASE);
        }
        uint64_t addr() const { return reinterpret_cast<uint64_t>(address); }
    };
}

TEST(query_describes_a_committed_readwrite_page) {
    scratch_page page;
    CHECK(page.address != nullptr);

    const auto region = debug_harness::mem::query(page.addr());
    CHECK(region.valid);
    CHECK(region.readable);
    CHECK(region.writable);
    CHECK(!region.executable);
    CHECK(!region.guarded);
    CHECK_EQ(region.state, static_cast<DWORD>(MEM_COMMIT));
}

TEST(query_attributes_a_code_address_to_this_module_and_section) {
    const auto region = debug_harness::mem::query(reinterpret_cast<uint64_t>(&debug_harness::mem::query));
    CHECK(region.valid);
    CHECK(region.readable);
    CHECK(region.executable);
    CHECK(region.module_name.find("debug_harness_tests") != std::string::npos);
    CHECK_STR_EQ(region.section_name, ".text");
    CHECK(region.module_base != 0);
}

TEST(query_reports_an_unmapped_address_as_invalid) {
    const auto region = debug_harness::mem::query(0x10ull);
    CHECK(!region.valid);
}

TEST(query_of_null_is_invalid) {
    CHECK(!debug_harness::mem::query(0).valid);
}

TEST(safe_read_reads_a_known_global) {
    int value = 0;
    CHECK(debug_harness::mem::safe_read(reinterpret_cast<uint64_t>(&known_global), &value, sizeof(value)));
    CHECK_EQ(value, 0x11223344);
}

TEST(safe_read_refuses_null) {
    uint64_t value = 0;
    CHECK(!debug_harness::mem::safe_read(0, &value, sizeof(value)));
}

TEST(safe_read_refuses_an_unmapped_address) {
    uint64_t value = 0;
    CHECK(!debug_harness::mem::safe_read(0x10ull, &value, sizeof(value)));
}

TEST(safe_read_refuses_a_zero_or_oversized_length) {
    uint8_t buffer[8] = {};
    const auto addr = reinterpret_cast<uint64_t>(&known_global);
    CHECK(!debug_harness::mem::safe_read(addr, buffer, 0));
    CHECK(!debug_harness::mem::safe_read(addr, buffer, debug_harness::mem::max_read_bytes + 1));
}

TEST(safe_read_refuses_a_null_destination) {
    CHECK(!debug_harness::mem::safe_read(reinterpret_cast<uint64_t>(&known_global), nullptr, 4));
}

TEST(safe_read_refuses_a_page_noaccess_page) {
    scratch_page page;
    DWORD previous = 0;
    CHECK(VirtualProtect(page.address, 0x1000, PAGE_NOACCESS, &previous) != 0);

    uint64_t value = 0;
    CHECK(!debug_harness::mem::safe_read(page.addr(), &value, sizeof(value)));

    VirtualProtect(page.address, 0x1000, previous, &previous);
}

TEST(safe_read_refuses_a_guard_page) {
    scratch_page page;
    DWORD previous = 0;
    CHECK(VirtualProtect(page.address, 0x1000, PAGE_READWRITE | PAGE_GUARD, &previous) != 0);

    uint64_t value = 0;
    CHECK(!debug_harness::mem::safe_read(page.addr(), &value, sizeof(value)));

    VirtualProtect(page.address, 0x1000, previous, &previous);
}

TEST(safe_read_refuses_a_span_that_runs_off_the_end_of_a_region) {
    scratch_page page;
    // Start 8 bytes before the page end and ask for 64: the tail is unmapped.
    uint8_t buffer[64] = {};
    CHECK(!debug_harness::mem::safe_read(page.addr() + 0x1000 - 8, buffer, sizeof(buffer)));
}

TEST(safe_read_refuses_a_wrapping_span) {
    uint8_t buffer[16] = {};
    CHECK(!debug_harness::mem::safe_read(0xFFFFFFFFFFFFFFF0ull, buffer, sizeof(buffer)));
}

TEST(safe_read_u64_reads_a_qword) {
    const uint64_t source = 0x0123456789ABCDEFull;
    uint64_t value = 0;
    CHECK(debug_harness::mem::safe_read_u64(reinterpret_cast<uint64_t>(&source), value));
    CHECK_EQ(value, source);
}

TEST(safe_read_u64_fails_on_an_unmapped_address) {
    uint64_t value = 0;
    CHECK(!debug_harness::mem::safe_read_u64(0x10ull, value));
}

TEST(safe_read_c_string_reads_up_to_the_terminator) {
    const char* text = "PlayerCharacter";
    std::string out;
    CHECK(debug_harness::mem::safe_read_c_string(reinterpret_cast<uint64_t>(text), 64, out));
    CHECK_STR_EQ(out, "PlayerCharacter");
}

TEST(safe_read_c_string_honours_max_chars) {
    const char* text = "PlayerCharacter";
    std::string out;
    CHECK(debug_harness::mem::safe_read_c_string(reinterpret_cast<uint64_t>(text), 7, out));
    CHECK_STR_EQ(out, "PlayerC");
}

TEST(safe_read_c_string_fails_on_an_unmapped_address) {
    std::string out;
    CHECK(!debug_harness::mem::safe_read_c_string(0x10ull, 64, out));
}

TEST(safe_read_w_string_converts_to_utf8) {
    const wchar_t* text = L"Harness";
    std::string out;
    CHECK(debug_harness::mem::safe_read_w_string(reinterpret_cast<uint64_t>(text), 64, out));
    CHECK_STR_EQ(out, "Harness");
}

TEST(writes_armed_is_false_by_default) {
    debug_harness::mem::arm_writes(false);
    CHECK(!debug_harness::mem::writes_armed());
}

TEST(safe_write_is_refused_while_disarmed) {
    debug_harness::mem::arm_writes(false);
    scratch_page page;
    const uint32_t value = 0xDEADBEEF;
    size_t undo_index = 0;
    std::string error;
    CHECK(!debug_harness::mem::safe_write(page.addr(), &value, sizeof(value), false, "test", undo_index, error));
    CHECK(error.find("not armed") != std::string::npos);
}

TEST(safe_write_round_trips_when_armed) {
    debug_harness::mem::arm_writes(true);
    scratch_page page;

    const uint32_t original = 0x11112222;
    size_t seed_index = 0;
    std::string error;
    CHECK(debug_harness::mem::safe_write(page.addr(), &original, sizeof(original), false, "seed", seed_index, error));

    const uint32_t replacement = 0xDEADBEEF;
    size_t undo_index = 0;
    CHECK(debug_harness::mem::safe_write(page.addr(), &replacement, sizeof(replacement), false, "test", undo_index, error));

    uint32_t read_back = 0;
    CHECK(debug_harness::mem::safe_read(page.addr(), &read_back, sizeof(read_back)));
    CHECK_EQ(read_back, 0xDEADBEEFu);

    debug_harness::mem::arm_writes(false);
}

TEST(safe_write_records_the_old_bytes_and_revert_restores_them) {
    debug_harness::mem::arm_writes(true);
    scratch_page page;

    const uint32_t original = 0xAABBCCDD;
    size_t seed_index = 0;
    std::string error;
    CHECK(debug_harness::mem::safe_write(page.addr(), &original, sizeof(original), false, "seed", seed_index, error));

    const uint32_t replacement = 0x00000000;
    size_t undo_index = 0;
    CHECK(debug_harness::mem::safe_write(page.addr(), &replacement, sizeof(replacement), false, "test", undo_index, error));

    const auto log = debug_harness::mem::undo_log();
    CHECK(undo_index < log.size());
    CHECK_EQ(log[undo_index].old_bytes.size(), static_cast<size_t>(4));
    CHECK_EQ(log[undo_index].old_bytes[0], static_cast<uint8_t>(0xDD)); // little endian
    CHECK_EQ(log[undo_index].new_bytes[0], static_cast<uint8_t>(0x00));
    CHECK_STR_EQ(log[undo_index].source, "test");
    CHECK(!log[undo_index].reverted);

    CHECK(debug_harness::mem::revert(undo_index, error));

    uint32_t read_back = 0;
    CHECK(debug_harness::mem::safe_read(page.addr(), &read_back, sizeof(read_back)));
    CHECK_EQ(read_back, 0xAABBCCDDu);
    CHECK(debug_harness::mem::undo_log()[undo_index].reverted);

    debug_harness::mem::arm_writes(false);
}

TEST(revert_twice_is_refused) {
    debug_harness::mem::arm_writes(true);
    scratch_page page;

    const uint32_t value = 0x5A5A5A5A;
    size_t undo_index = 0;
    std::string error;
    CHECK(debug_harness::mem::safe_write(page.addr(), &value, sizeof(value), false, "test", undo_index, error));
    CHECK(debug_harness::mem::revert(undo_index, error));
    CHECK(!debug_harness::mem::revert(undo_index, error));
    CHECK(error.find("already reverted") != std::string::npos);

    debug_harness::mem::arm_writes(false);
}

TEST(revert_rejects_an_out_of_range_index) {
    std::string error;
    CHECK(!debug_harness::mem::revert(99999, error));
}

TEST(safe_write_refuses_an_oversized_payload) {
    debug_harness::mem::arm_writes(true);
    scratch_page page;
    std::vector<uint8_t> payload(debug_harness::mem::max_write_bytes + 1, 0xCC);
    size_t undo_index = 0;
    std::string error;
    CHECK(!debug_harness::mem::safe_write(page.addr(), payload.data(), payload.size(), false, "test", undo_index, error));
    debug_harness::mem::arm_writes(false);
}

TEST(safe_write_refuses_a_read_only_page_without_force) {
    debug_harness::mem::arm_writes(true);
    scratch_page page;
    DWORD previous = 0;
    CHECK(VirtualProtect(page.address, 0x1000, PAGE_READONLY, &previous) != 0);

    const uint32_t value = 0x12345678;
    size_t undo_index = 0;
    std::string error;
    CHECK(!debug_harness::mem::safe_write(page.addr(), &value, sizeof(value), false, "test", undo_index, error));
    CHECK(error.find("not writable") != std::string::npos);

    VirtualProtect(page.address, 0x1000, previous, &previous);
    debug_harness::mem::arm_writes(false);
}

TEST(safe_write_with_force_writes_a_read_only_page_and_restores_protection) {
    debug_harness::mem::arm_writes(true);
    scratch_page page;
    DWORD previous = 0;
    CHECK(VirtualProtect(page.address, 0x1000, PAGE_READONLY, &previous) != 0);

    const uint32_t value = 0x12345678;
    size_t undo_index = 0;
    std::string error;
    CHECK(debug_harness::mem::safe_write(page.addr(), &value, sizeof(value), true, "test", undo_index, error));

    uint32_t read_back = 0;
    CHECK(debug_harness::mem::safe_read(page.addr(), &read_back, sizeof(read_back)));
    CHECK_EQ(read_back, 0x12345678u);

    // Protection must be back to PAGE_READONLY.
    CHECK(!debug_harness::mem::query(page.addr()).writable);

    VirtualProtect(page.address, 0x1000, PAGE_READWRITE, &previous);
    debug_harness::mem::arm_writes(false);
}

TEST(safe_write_refuses_null_and_unmapped_addresses) {
    debug_harness::mem::arm_writes(true);
    const uint32_t value = 1;
    size_t undo_index = 0;
    std::string error;
    CHECK(!debug_harness::mem::safe_write(0, &value, sizeof(value), false, "test", undo_index, error));
    CHECK(!debug_harness::mem::safe_write(0x10ull, &value, sizeof(value), false, "test", undo_index, error));
    debug_harness::mem::arm_writes(false);
}

TEST(arm_writes_expires_after_its_timeout) {
    debug_harness::mem::arm_writes(true, 0); // 0 seconds: already expired
    CHECK(!debug_harness::mem::writes_armed());
    CHECK_EQ(debug_harness::mem::write_arm_seconds_left(), 0u);
}

TEST(write_arm_seconds_left_counts_down_from_the_timeout) {
    debug_harness::mem::arm_writes(true, 300);
    CHECK(debug_harness::mem::writes_armed());
    CHECK(debug_harness::mem::write_arm_seconds_left() > 290u);
    CHECK(debug_harness::mem::write_arm_seconds_left() <= 300u);
    debug_harness::mem::arm_writes(false);
}

TEST(undo_log_is_capped_at_its_capacity) {
    debug_harness::mem::arm_writes(true);
    scratch_page page;
    std::string error;
    size_t undo_index = 0;

    for (size_t i = 0; i < debug_harness::mem::undo_capacity + 10; ++i) {
        const uint8_t value = static_cast<uint8_t>(i);
        CHECK(debug_harness::mem::safe_write(page.addr(), &value, 1, false, "spam", undo_index, error));
    }
    CHECK(debug_harness::mem::undo_log().size() <= debug_harness::mem::undo_capacity);
    debug_harness::mem::arm_writes(false);
}

namespace {
    void classify_dummy_function() {}
    const char* const ascii_target = "SCR_PlayerCharacter";
}

TEST(classify_recognises_null) {
    const auto result = debug_harness::mem::classify(0);
    CHECK(result.kind == debug_harness::mem::kind::null);
}

TEST(classify_recognises_a_small_integer) {
    const auto result = debug_harness::mem::classify(0x130);
    CHECK(result.kind == debug_harness::mem::kind::small_int);
    CHECK(result.text.find("0x130") != std::string::npos);
}

TEST(classify_recognises_a_code_pointer) {
    const auto address = reinterpret_cast<uint64_t>(&classify_dummy_function);
    const auto result = debug_harness::mem::classify(address);
    CHECK(result.kind == debug_harness::mem::kind::code);
    CHECK(result.text.find("debug_harness_tests") != std::string::npos);
    CHECK(result.text.find("+0x") != std::string::npos);
}

TEST(classify_recognises_a_pointer_to_an_ascii_string) {
    const auto address = reinterpret_cast<uint64_t>(ascii_target);
    const auto result = debug_harness::mem::classify(address);
    CHECK(result.kind == debug_harness::mem::kind::ascii);
    CHECK(result.text.find("SCR_PlayerCharacter") != std::string::npos);
}

TEST(classify_recognises_a_heap_pointer) {
    scratch_page page;
    // Fill with non-ASCII, non-code bytes so it is not misread as a string.
    memset(page.address, 0x01, 0x100);
    const auto result = debug_harness::mem::classify(page.addr());
    CHECK(result.kind == debug_harness::mem::kind::heap_ptr);
    CHECK(result.text.find("readable") != std::string::npos);
}

TEST(classify_recognises_a_vtable) {
    scratch_page page;
    // Eight slots all pointing at executable memory looks like a vtable.
    auto* slots = static_cast<uint64_t*>(page.address);
    for (int i = 0; i < 8; ++i)
        slots[i] = reinterpret_cast<uint64_t>(&classify_dummy_function);

    DWORD previous = 0;
    // Read-only, as a real .rdata vtable would be.
    CHECK(VirtualProtect(page.address, 0x1000, PAGE_READONLY, &previous) != 0);

    const auto result = debug_harness::mem::classify(page.addr());
    CHECK(result.kind == debug_harness::mem::kind::vtable);
    CHECK(result.vtable_slots >= 8);

    VirtualProtect(page.address, 0x1000, previous, &previous);
}

TEST(classify_recognises_a_plausible_float_pair) {
    // Two floats: 1.5f and -2.25f.
    float pair[2] = {1.5f, -2.25f};
    uint64_t as_qword = 0;
    memcpy(&as_qword, pair, sizeof(as_qword));

    const auto result = debug_harness::mem::classify(as_qword);
    CHECK(result.kind == debug_harness::mem::kind::float_pair);
    CHECK(result.text.find("1.5") != std::string::npos);
}

TEST(classify_falls_back_to_garbage) {
    // Large, non-canonical, not a pointer, not plausible floats.
    const auto result = debug_harness::mem::classify(0x7ABCDEF012345678ull);
    CHECK(result.kind == debug_harness::mem::kind::garbage || result.kind == debug_harness::mem::kind::float_pair);
}

TEST(classify_never_faults_on_arbitrary_values) {
    // The point of the guard layer: no input may crash the classifier.
    const uint64_t nasty[] = {
        0x1ull, 0xFFFFFFFFFFFFFFFFull, 0x8000000000000000ull, 0xFFFF800000000000ull, 0x7FFFFFFFFFFFull, 0xDEADBEEFull};
    for (const auto value : nasty) {
        const auto result = debug_harness::mem::classify(value);
        CHECK(!result.text.empty());
    }
}
