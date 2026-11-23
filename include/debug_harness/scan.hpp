#pragma once

#include <cstdint>
#include <string>
#include <vector>

// ============================================================
// x64 Signature Scanner
// ============================================================
// Pattern format: "48 8B D9 48 8B 0D ? ? ? ? E8 ? ? ? ?"
//   - Hex bytes are literal matches.
//   - '?' or '??' matches any single byte (wildcard).
//
// After finding a match, use resolve_rip_relative() to decode a
// RIP-relative operand (MOV, LEA, CALL, JMP, ...) at a specific
// offset within the matched pattern.
//
// Common x64 RIP-relative instructions and their operand offsets:
//   Instruction                | Bytes                    | operand_offset | instr_len
//   ---------------------------|--------------------------|----------------|----------
//   MOV RAX, [rip+disp32]      | 48 8B 05 xx xx xx xx     | 3              | 7
//   MOV RCX, [rip+disp32]      | 48 8B 0D xx xx xx xx     | 3              | 7
//   MOV RDX, [rip+disp32]      | 48 8B 15 xx xx xx xx     | 3              | 7
//   MOV RBX, [rip+disp32]      | 48 8B 1D xx xx xx xx     | 3              | 7
//   MOV R8,  [rip+disp32]      | 4C 8B 05 xx xx xx xx     | 3              | 7
//   LEA RAX, [rip+disp32]      | 48 8D 05 xx xx xx xx     | 3              | 7
//   LEA RCX, [rip+disp32]      | 48 8D 0D xx xx xx xx     | 3              | 7
//   CALL rel32                 | E8 xx xx xx xx           | 1              | 5
//   JMP  rel32                 | E9 xx xx xx xx           | 1              | 5
//   CMP  [rip+disp32], reg     | 48 39 05 xx xx xx xx     | 3              | 7
//   MOV  [rip+disp32], RAX     | 48 89 05 xx xx xx xx     | 3              | 7
// ============================================================

namespace debug_harness::scan {

    struct pattern_byte {
        bool is_wildcard;
        uint8_t value;
    };

    struct scan_result {
        std::vector<uintptr_t> hits; // capped at the caller's max_hits
        size_t total_hits = 0;        // every match, even beyond max_hits
        bool pattern_valid = false;
    };

    // Parse an IDA-style signature into `out`.
    //
    // Returns false -- never throws -- on an empty pattern, a non-hex token, or a token
    // wider than one byte. HTTP clients supply these strings, so a throw here would
    // escape into host code.
    bool parse_pattern(const char* pattern, std::vector<pattern_byte>& out);

    // Scan [base, base+size) for the first occurrence. Returns 0 on failure.
    // Both range scanners walk the range with mem::query first and only read committed,
    // readable runs: unreadable pages are skipped, and no match spans one.
    uintptr_t find_pattern(uintptr_t base, size_t size, const char* pattern);

    // Base and SizeOfImage of the configured module (host_config::module_name, nullptr =
    // main executable). False if unavailable.
    bool module_range(uintptr_t& out_base, size_t& out_size);

    // Scan the configured module. Returns the match address, or 0 on failure.
    uintptr_t find_pattern(const char* pattern);

    // Scan [base, base+size) for every occurrence.
    //
    // `total_hits` counts all matches even when `hits` is capped at max_hits, which is
    // what makes "is this signature unique?" answerable -- find_pattern's first-match
    // result cannot distinguish one hit from forty.
    //
    // Overlapping matches are all reported: the cursor advances by one byte, not by
    // the pattern length.
    scan_result find_all(uintptr_t base, size_t size, const char* pattern, size_t max_hits);

    // Scan the whole configured module for every occurrence.
    scan_result find_all(const char* pattern, size_t max_hits);

    // Resolve a RIP-relative operand inside a matched instruction.
    //
    //   match_addr     - address returned by find_pattern (start of the matched bytes)
    //   operand_offset - byte offset from match_addr to the 4-byte disp32
    //   instr_len      - total length of the instruction containing the operand; RIP is
    //                   advanced past the *entire instruction* before adding disp32
    //
    // Formula: (match_addr + instr_len) + *(int32_t*)(match_addr + operand_offset)
    //
    // Example:
    //   auto match = scan::find_pattern("48 8B D9 48 8B 0D ? ? ? ? E8 ? ? ? ? 48 8B 15 ? ? ? ?");
    //   if (match) {
    //       auto rcx_target  = scan::resolve_rip_relative(match, 7, 11);   // MOV RCX, [rip+disp32]
    //       auto call_target = scan::resolve_rip_relative(match, 11, 15);  // CALL rel32
    //       auto rdx_target  = scan::resolve_rip_relative(match, 18, 22);  // MOV RDX, [rip+disp32]
    //   }
    uintptr_t resolve_rip_relative(uintptr_t match_addr, size_t operand_offset, size_t instr_len);

    // Find a pattern and resolve one RIP-relative operand. 0 if the pattern is absent.
    uintptr_t find_and_resolve(const char* pattern, size_t operand_offset, size_t instr_len);
}
