#include "debug_harness/scan.hpp"

#include <cctype>
#include <string>

#include "debug_harness/live.hpp"
#include "debug_harness/mem.hpp"

namespace debug_harness::scan {

    // Not in the header: an implementation detail of the two scanners.
    namespace {
        bool matches_at(const uint8_t* at, const std::vector<pattern_byte>& bytes) {
            for (size_t i = 0; i < bytes.size(); ++i) {
                if (!bytes[i].is_wildcard && at[i] != bytes[i].value) return false;
            }
            return true;
        }

        // Call `visit(run_base, run_size)` for each maximal run of committed, readable
        // memory inside [base, base+size). The scanners only ever touch bytes inside such
        // a run, so a PAGE_NOACCESS, guard or uncommitted page inside the range (a packed
        // or protected image, a range typed over HTTP) is skipped instead of faulting the
        // calling thread. A match is never reported across a gap. `visit` returns false
        // to stop early.
        template <typename Visit> void for_each_readable_run(uintptr_t base, size_t size, Visit&& visit) {
            const uint64_t end = static_cast<uint64_t>(base) + size;
            if (end < base) return; // wraps
            uint64_t cursor = base;
            uint64_t run_start = 0;
            bool in_run = false;
            while (cursor < end) {
                const auto region = debug_harness::mem::query(cursor);
                const uint64_t region_end = region.region_base + region.region_size;
                const bool readable = region.valid && region.readable;
                if (readable && !in_run) {
                    run_start = cursor;
                    in_run = true;
                } else if (!readable && in_run) {
                    in_run = false;
                    if (!visit(static_cast<uintptr_t>(run_start), static_cast<size_t>(cursor - run_start))) return;
                }
                if (region_end <= cursor) {
                    // VirtualQuery failed (or made no progress): treat one page as unreadable.
                    if (in_run) {
                        in_run = false;
                        if (!visit(static_cast<uintptr_t>(run_start), static_cast<size_t>(cursor - run_start))) return;
                    }
                    cursor = (cursor | 0xFFFull) + 1;
                    continue;
                }
                cursor = region_end < end ? region_end : end;
            }
            if (in_run) visit(static_cast<uintptr_t>(run_start), static_cast<size_t>(end - run_start));
        }
    }

    bool parse_pattern(const char* pattern, std::vector<pattern_byte>& out) {
        out.clear();
        if (!pattern) return false;

        const std::string text(pattern);
        size_t index = 0;

        while (index < text.size()) {
            while (index < text.size() && std::isspace(static_cast<unsigned char>(text[index])))
                ++index;
            if (index >= text.size()) break;

            const size_t token_start = index;
            while (index < text.size() && !std::isspace(static_cast<unsigned char>(text[index])))
                ++index;
            const std::string token = text.substr(token_start, index - token_start);

            if (token == "?" || token == "??") {
                out.push_back({true, 0});
                continue;
            }

            if (token.size() != 1 && token.size() != 2) {
                out.clear();
                return false;
            }

            unsigned int value = 0;
            for (const char digit : token) {
                const auto ch = static_cast<unsigned char>(digit);
                unsigned int nibble = 0;
                if (ch >= '0' && ch <= '9')
                    nibble = ch - '0';
                else if (ch >= 'a' && ch <= 'f')
                    nibble = ch - 'a' + 10;
                else if (ch >= 'A' && ch <= 'F')
                    nibble = ch - 'A' + 10;
                else {
                    out.clear();
                    return false;
                }
                value = (value << 4) | nibble;
            }

            out.push_back({false, static_cast<uint8_t>(value)});
        }

        if (out.empty()) return false;
        return true;
    }

    uintptr_t find_pattern(uintptr_t base, size_t size, const char* pattern) {
        std::vector<pattern_byte> bytes;
        if (!parse_pattern(pattern, bytes)) return 0;
        if (bytes.size() > size) return 0;

        uintptr_t found = 0;
        for_each_readable_run(base, size, [&](uintptr_t run_base, size_t run_size) {
            if (bytes.size() > run_size) return true;
            const auto scan_start = reinterpret_cast<const uint8_t*>(run_base);
            const auto scan_end = scan_start + run_size - bytes.size();
            for (const uint8_t* current = scan_start; current <= scan_end; ++current) {
                if (matches_at(current, bytes)) {
                    found = reinterpret_cast<uintptr_t>(current);
                    return false;
                }
            }
            return true;
        });
        return found;
    }

    bool module_range(uintptr_t& out_base, size_t& out_size) {
        // Same module `live` reports for ida:/rva:/@base, so a scan hit and an rva agree.
        const uint64_t base = debug_harness::live::module_base();
        const size_t size = debug_harness::live::module_image_size();
        if (base == 0 || size == 0) return false;
        out_base = static_cast<uintptr_t>(base);
        out_size = size;
        return true;
    }

    uintptr_t find_pattern(const char* pattern) {
        uintptr_t base = 0;
        size_t size = 0;
        if (!module_range(base, size)) return 0;
        return find_pattern(base, size, pattern);
    }

    scan_result find_all(uintptr_t base, size_t size, const char* pattern, size_t max_hits) {
        scan_result result;

        std::vector<pattern_byte> bytes;
        if (!parse_pattern(pattern, bytes)) return result;

        result.pattern_valid = true;
        if (bytes.size() > size) return result;

        for_each_readable_run(base, size, [&](uintptr_t run_base, size_t run_size) {
            if (bytes.size() > run_size) return true;
            const auto scan_start = reinterpret_cast<const uint8_t*>(run_base);
            const auto scan_end = scan_start + run_size - bytes.size();
            for (const uint8_t* current = scan_start; current <= scan_end; ++current) {
                if (!matches_at(current, bytes)) continue;
                ++result.total_hits;
                if (result.hits.size() < max_hits) result.hits.push_back(reinterpret_cast<uintptr_t>(current));
            }
            return true;
        });
        return result;
    }

    scan_result find_all(const char* pattern, size_t max_hits) {
        uintptr_t base = 0;
        size_t size = 0;
        if (!module_range(base, size)) {
            scan_result result;
            std::vector<pattern_byte> bytes;
            result.pattern_valid = parse_pattern(pattern, bytes);
            return result;
        }
        return find_all(base, size, pattern, max_hits);
    }

    uintptr_t resolve_rip_relative(uintptr_t match_addr, size_t operand_offset, size_t instr_len) {
        const auto displacement = *reinterpret_cast<const int32_t*>(match_addr + operand_offset);
        return match_addr + instr_len + displacement;
    }

    uintptr_t find_and_resolve(const char* pattern, size_t operand_offset, size_t instr_len) {
        const auto match = find_pattern(pattern);
        if (!match) return 0;
        return resolve_rip_relative(match, operand_offset, instr_len);
    }
}
