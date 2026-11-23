#include "debug_harness/expr.hpp"

#include <cctype>

namespace {

    using debug_harness::expr::env;
    using debug_harness::expr::result;
    using debug_harness::expr::step;

    void skip_spaces(const std::string& text, size_t& index) {
        while (index < text.size() && std::isspace(static_cast<unsigned char>(text[index])))
            ++index;
    }

    bool starts_with(const std::string& text, size_t index, const char* prefix) {
        size_t offset = 0;
        while (prefix[offset] != '\0') {
            if (index + offset >= text.size() || text[index + offset] != prefix[offset]) return false;
            ++offset;
        }
        return true;
    }

    std::string to_hex_label(uint64_t value) {
        static const char* digits = "0123456789ABCDEF";
        std::string out;
        if (value == 0) return "0x0";
        while (value != 0) {
            out.insert(out.begin(), digits[value & 0xF]);
            value >>= 4;
        }
        return "0x" + out;
    }

    result failure(const std::string& message, size_t at, std::vector<step> steps) {
        result result;
        result.ok = false;
        result.error = message;
        result.error_at = at;
        result.steps = std::move(steps);
        return result;
    }

    // Parse "0x" followed by at least one hex digit. Wraps on overflow rather than
    // rejecting, matching the address arithmetic below.
    bool parse_hex(const std::string& text, size_t& index, uint64_t& out) {
        if (!starts_with(text, index, "0x") && !starts_with(text, index, "0X")) return false;
        size_t cursor = index + 2;

        uint64_t value = 0;
        size_t digit_count = 0;
        while (cursor < text.size()) {
            const auto ch = static_cast<unsigned char>(text[cursor]);
            uint64_t nibble = 0;
            if (ch >= '0' && ch <= '9')
                nibble = ch - '0';
            else if (ch >= 'a' && ch <= 'f')
                nibble = ch - 'a' + 10;
            else if (ch >= 'A' && ch <= 'F')
                nibble = ch - 'A' + 10;
            else
                break;
            value = (value << 4) | nibble;
            ++digit_count;
            ++cursor;
        }

        if (digit_count == 0) return false;

        index = cursor;
        out = value;
        return true;
    }

    bool is_root_name_char(char ch) {
        const auto value = static_cast<unsigned char>(ch);
        return std::isalnum(value) || ch == '_' || ch == '.';
    }

    bool is_symbol_char(char ch) {
        const auto value = static_cast<unsigned char>(ch);
        return std::isalnum(value) || ch == '_' || ch == ':';
    }

    // An addend is either a 0x-prefixed hex literal or a catalog symbol name.
    // `out_label` is what the step trace shows.
    bool parse_addend(const std::string& text, size_t& index, const env& env, uint64_t& out_value, std::string& out_label,
                     std::string& out_error) {
        if (index >= text.size()) {
            out_error = "expected a hex addend or offset name";
            return false;
        }

        if (parse_hex(text, index, out_value)) {
            out_label = to_hex_label(out_value);
            return true;
        }

        const size_t name_start = index;
        size_t cursor = index;
        while (cursor < text.size() && is_symbol_char(text[cursor]))
            ++cursor;

        if (cursor == name_start) {
            out_error = "expected a 0x-prefixed hex addend or an offset name";
            return false;
        }

        const std::string name = text.substr(name_start, cursor - name_start);
        if (!env.symbol(name, out_value)) {
            out_error = "unknown offset name '" + name + "'";
            return false;
        }

        index = cursor;
        out_label = name + " (" + to_hex_label(out_value) + ")";
        return true;
    }
}

namespace debug_harness::expr {

    result evaluate(const std::string& expression, const env& env) {
        std::vector<step> steps;
        size_t index = 0;

        skip_spaces(expression, index);
        if (index >= expression.size()) return failure("expression is empty", 0, steps);

        const size_t root_at = index;
        uint64_t address = 0;
        step root_step;
        root_step.deref = false;
        root_step.ok = true;

        if (expression[index] == '@') {
            const size_t name_start = index + 1;
            size_t cursor = name_start;
            while (cursor < expression.size() && is_root_name_char(expression[cursor]))
                ++cursor;

            if (cursor == name_start) return failure("expected a root name after '@'", root_at, steps);

            const std::string name = expression.substr(name_start, cursor - name_start);
            std::string note;
            if (!env.root(name, address, note)) return failure("unknown root '@" + name + "'", root_at, steps);

            root_step.label = "@" + name;
            root_step.note = note;
            index = cursor;
        } else {
            enum class root_kind { va, rva, ida } kind;
            if (starts_with(expression, index, "va:")) {
                kind = root_kind::va;
                index += 3;
            } else if (starts_with(expression, index, "rva:")) {
                kind = root_kind::rva;
                index += 4;
            } else if (starts_with(expression, index, "ida:")) {
                kind = root_kind::ida;
                index += 4;
            } else {
                return failure("expression must start with '@root', 'va:', 'rva:' or 'ida:'", root_at, steps);
            }

            const size_t hex_at = index;
            uint64_t literal = 0;
            if (!parse_hex(expression, index, literal))
                return failure("expected a 0x-prefixed hex address", hex_at, steps);

            switch (kind) {
            case root_kind::va:
                address = literal;
                root_step.label = "va:" + to_hex_label(literal);
                root_step.note = "absolute";
                break;
            case root_kind::rva:
                address = env.module_base() + literal;
                root_step.label = "rva:" + to_hex_label(literal);
                root_step.note = "module base + rva";
                break;
            case root_kind::ida:
                if (literal < env.preferred_base())
                    return failure("address is below the preferred image base " + to_hex_label(env.preferred_base()),
                                   hex_at, steps);
                address = env.module_base() + (literal - env.preferred_base());
                root_step.label = "ida:" + to_hex_label(literal);
                root_step.note = "rebased through the preferred image base";
                break;
            }
        }

        root_step.address = address;
        root_step.value = address;
        steps.push_back(root_step);

        // Suffix loop. Suffixes apply left to right.
        for (;;) {
            skip_spaces(expression, index);
            if (index >= expression.size()) break;

            const char ch = expression[index];

            if (ch == '+') {
                const size_t plus_at = index;
                ++index;
                skip_spaces(expression, index);

                uint64_t addend = 0;
                std::string label;
                std::string error;
                const size_t addend_at = index;
                if (!parse_addend(expression, index, env, addend, label, error))
                    return failure(error, index >= expression.size() ? plus_at : addend_at, steps);

                address += addend; // deliberately wraps

                step step;
                step.label = "+" + label;
                step.address = address;
                step.value = address;
                step.deref = false;
                step.ok = true;
                steps.push_back(step);
                continue;
            }

            if (ch == '[') {
                const size_t open_at = index;
                ++index;
                skip_spaces(expression, index);

                uint64_t addend = 0;
                std::string label = "";

                if (index < expression.size() && expression[index] == '+') {
                    ++index;
                    skip_spaces(expression, index);

                    std::string error;
                    const size_t addend_at = index;
                    if (!parse_addend(expression, index, env, addend, label, error))
                        return failure(error, addend_at, steps);
                    label = "+" + label;
                    skip_spaces(expression, index);
                }

                if (index >= expression.size() || expression[index] != ']')
                    return failure("expected ']' to close the dereference", open_at, steps);
                ++index;

                const uint64_t read_from = address + addend; // deliberately wraps

                step step;
                step.label = "[" + label + "]";
                step.address = read_from;
                step.deref = true;

                uint64_t read_value = 0;
                std::string note;
                if (!env.read_u64(read_from, read_value, note)) {
                    step.ok = false;
                    step.value = 0;
                    step.note = note;
                    steps.push_back(step);
                    return failure("could not read qword at " + to_hex_label(read_from), open_at, steps);
                }

                step.ok = true;
                step.value = read_value;
                step.note = note;
                steps.push_back(step);

                address = read_value;
                continue;
            }

            return failure("expected '+', '[' or end of expression", index, steps);
        }

        result result;
        result.ok = true;
        result.address = address;
        result.steps = std::move(steps);
        return result;
    }
}
