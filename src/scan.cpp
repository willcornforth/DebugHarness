#include "debug_harness/scan.hpp"

#include <cctype>
#include <string>

#include "debug_harness/live.hpp"

namespace debug_harness::scan {

    // Not in the header: an implementation detail of the two scanners.
    namespace {
        bool matches_at(const uint8_t* at, const std::vector<pattern_byte>& bytes) {
            for (size_t i = 0; i < bytes.size(); ++i) {
                if (!bytes[i].is_wildcard && at[i] != bytes[i].value) return false;
            }
            return true;
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

        const auto scan_start = reinterpret_cast<const uint8_t*>(base);
        const auto scan_end = scan_start + size - bytes.size();

        for (const uint8_t* current = scan_start; current <= scan_end; ++current) {
            if (matches_at(current, bytes)) return reinterpret_cast<uintptr_t>(current);
        }
        return 0;
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

        const auto scan_start = reinterpret_cast<const uint8_t*>(base);
        const auto scan_end = scan_start + size - bytes.size();

        for (const uint8_t* current = scan_start; current <= scan_end; ++current) {
            if (!matches_at(current, bytes)) continue;
            ++result.total_hits;
            if (result.hits.size() < max_hits) result.hits.push_back(reinterpret_cast<uintptr_t>(current));
        }
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
