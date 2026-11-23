#pragma once

#include <cstdint>
#include <string>
#include <utility>
#include <vector>

// HTTP/1.0 request parsing and response building, plus a small JSON writer.
//
// Only what a curl-on-loopback debug harness needs: one request per connection,
// Connection: close, no keep-alive, no chunked encoding, no multipart. Every feature
// left out is a parser bug that cannot happen.
namespace debug_harness::http {

    struct request {
        std::string method;
        std::string path;
        std::string body;
        std::vector<std::pair<std::string, std::string>> query;

        bool has(const std::string& key) const;
        std::string get(const std::string& key, const std::string& fallback = "") const;

        // Accepts "0x"-prefixed hex or plain decimal. False if absent or malformed.
        bool get_u64(const std::string& key, uint64_t& out) const;

        // "1"/"true"/"yes"/"on" are true; "0"/"false"/"no"/"off" are false.
        bool get_bool(const std::string& key, bool fallback) const;
    };

    // Offset just past the "\r\n\r\n" header terminator, or npos if not yet present.
    size_t header_end(const std::string& raw);

    // Content-Length value, 0 when the header is absent. Case-insensitive.
    size_t content_length(const std::string& raw);

    // Parse a complete request. False on a malformed request line or a path that does
    // not start with '/'.
    bool parse_request(const std::string& raw, request& out, std::string& out_error);

    std::string url_decode(const std::string& in);

    std::string build_response(int status, const std::string& content_type, const std::string& body);
}

namespace debug_harness::json {

    std::string escape(const std::string& in);

    // Append-only writer. Emits compact JSON; commas and nesting are tracked for you.
    class writer {
    public:
        writer& begin_object();
        writer& end_object();
        writer& begin_array();
        writer& end_array();
        writer& key(const std::string& key);
        writer& boolean(bool value);
        writer& u64(uint64_t value);
        writer& i64(int64_t value);
        writer& num(double value);
        writer& hex(uint64_t value); // written as a "0x..." string
        writer& str(const std::string& value);
        writer& null();

        std::string take();

    private:
        void comma();

        std::string out_;
        std::vector<bool> need_comma_; // one entry per open object/array
        bool after_key_ = false;
    };
}
