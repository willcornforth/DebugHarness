#pragma once

#include <Windows.h>

#include <cstdint>
#include <string>
#include <vector>

// Guarded access to this process's memory.
//
// Nothing else in the debug harness may dereference a host pointer. Every read here
// validates the region before touching it and then performs the copy under SEH, so a
// wrong offset yields a structured failure instead of taking the host down. That
// property is the reason the harness is safe to point at a live process, and no caller
// may bypass it.
namespace debug_harness::mem {

    struct region_info {
        bool valid = false;
        uint64_t allocation_base = 0;
        uint64_t region_base = 0;
        size_t region_size = 0;
        DWORD protect = 0;
        DWORD state = 0;
        DWORD type = 0;
        bool readable = false;
        bool writable = false;
        bool executable = false;
        bool guarded = false;
        std::string module_name;  // "" when the address is not inside a loaded module
        std::string section_name; // ".text", ".rdata", ... "" when unknown
        uint64_t module_base = 0;
    };

    // VirtualQuery plus module and PE-section attribution. `valid` is false for
    // unmapped or reserved-but-uncommitted addresses, and for address 0.
    region_info query(uint64_t address);

    constexpr size_t max_read_bytes = 4096;

    // Read `size` bytes. False when the span is not entirely committed and readable,
    // when `size` is 0 or above max_read_bytes, when `out` is null, or when the copy
    // faults anyway. Spans crossing a region boundary are validated region by region.
    bool safe_read(uint64_t address, void* out, size_t size);

    bool safe_read_u64(uint64_t address, uint64_t& out);

    // Read a NUL-terminated narrow string, stopping at `max_chars`. False if the first
    // byte is unreadable; a string truncated by max_chars still succeeds.
    bool safe_read_c_string(uint64_t address, size_t max_chars, std::string& out);

    // As above for UTF-16, converted to UTF-8.
    bool safe_read_w_string(uint64_t address, size_t max_chars, std::string& out_utf8);

    // --- writes -------------------------------------------------------------
    //
    // Writes are refused unless explicitly armed, the arm state expires on its own,
    // and every write keeps its original bytes so it can be reverted. None of that
    // makes writing to a live process safe; it only bounds the damage.

    struct write_record {
        uint64_t address = 0;
        std::vector<uint8_t> old_bytes;
        std::vector<uint8_t> new_bytes;
        uint64_t timestamp_ms = 0; // GetTickCount64 at the time of the write
        std::string source = "";  // "http" or "gui", for the UI write log
        bool reverted = false;
    };

    constexpr size_t max_write_bytes = 256;
    constexpr size_t undo_capacity = 64;

    // Arm or disarm writes. `auto_disarm_seconds` of 0 arms nothing (immediately
    // expired), which is what the tests rely on. Only the in-process UI calls this:
    // arming must never be reachable over HTTP.
    void arm_writes(bool armed, unsigned int auto_disarm_seconds = 300);

    // True only while armed and unexpired. Performs the expiry check, so calling it
    // is what actually disarms a stale arm.
    bool writes_armed();

    // Seconds until auto-disarm; 0 when disarmed or expired.
    unsigned int write_arm_seconds_left();

    // Write `size` bytes, recording the originals in the undo buffer.
    //
    // Refused when writes are disarmed, `size` is 0 or above max_write_bytes, the span
    // is not committed, or the span is not writable and `force` is false. With `force`
    // the protection is temporarily raised to PAGE_EXECUTE_READWRITE and restored
    // afterwards. On success `out_undo_index` indexes into undo_log().
    bool safe_write(uint64_t address, const void* data, size_t size, bool force, const std::string& source,
                   size_t& out_undo_index, std::string& out_error);

    // A snapshot copy -- the caller may be on a different thread than the writer.
    std::vector<write_record> undo_log();

    // Restore the original bytes of one recorded write. Refused for an unknown index
    // or an entry already reverted. Ignores the arm state: undoing damage must always
    // be possible.
    bool revert(size_t undo_index, std::string& out_error);

    // --- classification -----------------------------------------------------
    //
    // What a qword "looks like". A heuristic, and presented as one: vtable detection
    // in particular will fire on data that happens to hold code-like pointers. It
    // exists so GET /struct can propose a layout instead of printing raw hex.

    enum class kind {
        null,
        code,      // points into an executable section
        vtable,    // points at a read-only run of code pointers
        heap_ptr,   // points at readable non-module memory
        stack_ptr,  // points into the current thread's stack
        small_int,  // small enough to be a count, index or offset
        float_pair, // the two halves are both plausible floats
        ascii,     // points at printable NUL-terminated text
        garbage
    };

    struct classification {
        kind kind = kind::garbage;
        std::string text;         // human-readable, e.g. "code:host.exe+0x7103C0"
        uint64_t vtable_slots = 0; // only meaningful for kind::vtable
    };

    // Never faults, whatever the input: every probe goes through safe_read.
    classification classify(uint64_t qword);
}
