#include "debug_harness/http.hpp"

#include <cctype>
#include <cmath>
#include <format>

namespace {

    std::string to_lower(const std::string& text) {
        std::string out = text;
        for (char& ch : out)
            ch = static_cast<char>(std::tolower(static_cast<unsigned char>(ch)));
        return out;
    }

    int hex_digit(char ch) {
        const auto value = static_cast<unsigned char>(ch);
        if (value >= '0' && value <= '9') return value - '0';
        if (value >= 'a' && value <= 'f') return value - 'a' + 10;
        if (value >= 'A' && value <= 'F') return value - 'A' + 10;
        return -1;
    }

    const char* status_text(int status) {
        switch (status) {
        case 200:
            return "OK";
        case 400:
            return "Bad Request";
        case 403:
            return "Forbidden";
        case 404:
            return "Not Found";
        case 413:
            return "Payload Too Large";
        case 500:
            return "Internal Server Error";
        case 504:
            return "Gateway Timeout";
        default:
            return "Unknown";
        }
    }
}

namespace debug_harness::http {

    bool request::has(const std::string& key) const {
        for (const auto& entry : query) {
            if (entry.first == key) return true;
        }
        return false;
    }

    std::string request::get(const std::string& key, const std::string& fallback) const {
        for (const auto& entry : query) {
            if (entry.first == key) return entry.second;
        }
        return fallback;
    }

    bool request::get_u64(const std::string& key, uint64_t& out) const {
        if (!has(key)) return false;
        const std::string text = get(key);
        if (text.empty()) return false;

        size_t index = 0;
        int base = 10;
        if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
            index = 2;
            base = 16;
        }

        uint64_t value = 0;
        size_t digits = 0;
        for (; index < text.size(); ++index) {
            const int digit = hex_digit(text[index]);
            if (digit < 0 || digit >= base) return false;
            value = value * static_cast<uint64_t>(base) + static_cast<uint64_t>(digit);
            ++digits;
        }
        if (digits == 0) return false;

        out = value;
        return true;
    }

    bool request::get_bool(const std::string& key, bool fallback) const {
        if (!has(key)) return fallback;
        const std::string text = to_lower(get(key));
        if (text == "1" || text == "true" || text == "yes" || text == "on") return true;
        if (text == "0" || text == "false" || text == "no" || text == "off") return false;
        return fallback;
    }

    size_t header_end(const std::string& raw) {
        const size_t found = raw.find("\r\n\r\n");
        if (found == std::string::npos) return std::string::npos;
        return found + 4;
    }

    size_t content_length(const std::string& raw) {
        const std::string lowered = to_lower(raw);
        const size_t found = lowered.find("content-length:");
        if (found == std::string::npos) return 0;

        size_t index = found + 15;
        while (index < raw.size() && (raw[index] == ' ' || raw[index] == '\t'))
            ++index;

        size_t value = 0;
        size_t digits = 0;
        while (index < raw.size() && raw[index] >= '0' && raw[index] <= '9') {
            value = value * 10 + static_cast<size_t>(raw[index] - '0');
            ++digits;
            ++index;
        }
        return digits == 0 ? 0 : value;
    }

    std::string url_decode(const std::string& in) {
        std::string out;
        out.reserve(in.size());

        for (size_t i = 0; i < in.size(); ++i) {
            if (in[i] == '+') {
                out.push_back(' ');
                continue;
            }
            if (in[i] == '%' && i + 2 < in.size()) {
                const int high = hex_digit(in[i + 1]);
                const int low = hex_digit(in[i + 2]);
                if (high >= 0 && low >= 0) {
                    out.push_back(static_cast<char>((high << 4) | low));
                    i += 2;
                    continue;
                }
            }
            out.push_back(in[i]);
        }
        return out;
    }

    bool parse_request(const std::string& raw, request& out, std::string& out_error) {
        out_error.clear();
        out = request();

        const size_t line_end = raw.find("\r\n");
        const std::string line = raw.substr(0, line_end == std::string::npos ? raw.size() : line_end);

        const size_t first_space = line.find(' ');
        if (first_space == std::string::npos) {
            out_error = "malformed request line";
            return false;
        }
        const size_t second_space = line.find(' ', first_space + 1);
        if (second_space == std::string::npos) {
            out_error = "malformed request line";
            return false;
        }

        out.method = line.substr(0, first_space);
        const std::string target = line.substr(first_space + 1, second_space - first_space - 1);
        if (out.method.empty() || target.empty() || target[0] != '/') {
            out_error = "malformed request target";
            return false;
        }

        const size_t question_mark = target.find('?');
        out.path = url_decode(target.substr(0, question_mark));

        if (question_mark != std::string::npos) {
            const std::string query_string = target.substr(question_mark + 1);
            size_t cursor = 0;
            while (cursor <= query_string.size() && !query_string.empty()) {
                size_t next = query_string.find('&', cursor);
                if (next == std::string::npos) next = query_string.size();

                const std::string pair = query_string.substr(cursor, next - cursor);
                if (!pair.empty()) {
                    const size_t equals = pair.find('=');
                    if (equals == std::string::npos)
                        out.query.emplace_back(url_decode(pair), std::string());
                    else
                        out.query.emplace_back(url_decode(pair.substr(0, equals)), url_decode(pair.substr(equals + 1)));
                }

                if (next >= query_string.size()) break;
                cursor = next + 1;
            }
        }

        const size_t body_start = header_end(raw);
        if (body_start != std::string::npos && body_start <= raw.size()) out.body = raw.substr(body_start);

        return true;
    }

    std::string build_response(int status, const std::string& content_type, const std::string& body) {
        return std::format("HTTP/1.0 {} {}\r\n"
                           "Content-Type: {}\r\n"
                           "Content-Length: {}\r\n"
                           "Cache-Control: no-store\r\n"
                           "Connection: close\r\n"
                           "\r\n"
                           "{}",
                           status, status_text(status), content_type, body.size(), body);
    }
}

namespace debug_harness::json {

    std::string escape(const std::string& in) {
        std::string out;
        out.reserve(in.size() + 8);

        for (const char raw_char : in) {
            const auto ch = static_cast<unsigned char>(raw_char);
            switch (ch) {
            case '"':
                out += "\\\"";
                break;
            case '\\':
                out += "\\\\";
                break;
            case '\n':
                out += "\\n";
                break;
            case '\r':
                out += "\\r";
                break;
            case '\t':
                out += "\\t";
                break;
            case '\b':
                out += "\\b";
                break;
            case '\f':
                out += "\\f";
                break;
            default:
                if (ch < 0x20) {
                    out += std::format("\\u{:04X}", ch);
                } else {
                    out.push_back(raw_char);
                }
                break;
            }
        }
        return out;
    }

    void writer::comma() {
        // A value following a key never gets a comma; the key already emitted one.
        if (after_key_) {
            after_key_ = false;
            return;
        }
        if (!need_comma_.empty()) {
            if (need_comma_.back()) out_.push_back(',');
            need_comma_.back() = true;
        }
    }

    writer& writer::begin_object() {
        comma();
        out_.push_back('{');
        need_comma_.push_back(false);
        return *this;
    }

    writer& writer::end_object() {
        out_.push_back('}');
        if (!need_comma_.empty()) need_comma_.pop_back();
        return *this;
    }

    writer& writer::begin_array() {
        comma();
        out_.push_back('[');
        need_comma_.push_back(false);
        return *this;
    }

    writer& writer::end_array() {
        out_.push_back(']');
        if (!need_comma_.empty()) need_comma_.pop_back();
        return *this;
    }

    writer& writer::key(const std::string& key) {
        comma();
        out_.push_back('"');
        out_ += escape(key);
        out_ += "\":";
        after_key_ = true;
        return *this;
    }

    writer& writer::boolean(bool value) {
        comma();
        out_ += value ? "true" : "false";
        return *this;
    }

    writer& writer::u64(uint64_t value) {
        comma();
        out_ += std::format("{}", value);
        return *this;
    }

    writer& writer::i64(int64_t value) {
        comma();
        out_ += std::format("{}", value);
        return *this;
    }

    writer& writer::num(double value) {
        comma();
        // JSON has no NaN or infinity, and /read?as=f32 over arbitrary memory meets
        // both constantly; "nan" would make the whole body unparseable.
        if (!std::isfinite(value)) {
            out_ += "null";
            return *this;
        }
        out_ += std::format("{:g}", value);
        return *this;
    }

    writer& writer::hex(uint64_t value) {
        comma();
        out_ += std::format("\"0x{:X}\"", value);
        return *this;
    }

    writer& writer::str(const std::string& value) {
        comma();
        out_.push_back('"');
        out_ += escape(value);
        out_.push_back('"');
        return *this;
    }

    writer& writer::null() {
        comma();
        out_ += "null";
        return *this;
    }

    std::string writer::take() {
        return out_;
    }
}
