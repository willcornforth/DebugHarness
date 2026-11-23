#include "harness.hpp"

#include "debug_harness/http.hpp"

#include <string>

TEST(parse_request_reads_the_method_and_path) {
    debug_harness::http::request request;
    std::string error;
    CHECK(debug_harness::http::parse_request("GET /ping HTTP/1.1\r\nHost: x\r\n\r\n", request, error));
    CHECK_STR_EQ(request.method, "GET");
    CHECK_STR_EQ(request.path, "/ping");
    CHECK(request.query.empty());
}

TEST(parse_request_reads_query_parameters) {
    debug_harness::http::request request;
    std::string error;
    CHECK(debug_harness::http::parse_request("GET /read?e=va:0x10&n=8 HTTP/1.0\r\n\r\n", request, error));
    CHECK_STR_EQ(request.path, "/read");
    CHECK_EQ(request.query.size(), static_cast<size_t>(2));
    CHECK_STR_EQ(request.get("e"), "va:0x10");
    CHECK_STR_EQ(request.get("n"), "8");
}

TEST(parse_request_url_decodes_parameter_values) {
    debug_harness::http::request request;
    std::string error;
    // %40local.character%5B%2B0x130%5D  ==  @local.character[+0x130]
    CHECK(debug_harness::http::parse_request("GET /chain?e=%40local.character%5B%2B0x130%5D HTTP/1.0\r\n\r\n", request, error));
    CHECK_STR_EQ(request.get("e"), "@local.character[+0x130]");
}

TEST(parse_request_decodes_plus_as_space) {
    debug_harness::http::request request;
    std::string error;
    CHECK(debug_harness::http::parse_request("GET /scan?p=48+8B+%3F HTTP/1.0\r\n\r\n", request, error));
    CHECK_STR_EQ(request.get("p"), "48 8B ?");
}

TEST(parse_request_handles_a_valueless_parameter) {
    debug_harness::http::request request;
    std::string error;
    CHECK(debug_harness::http::parse_request("GET /offsets?filter HTTP/1.0\r\n\r\n", request, error));
    CHECK(request.has("filter"));
    CHECK_STR_EQ(request.get("filter"), "");
}

TEST(parse_request_reads_a_post_body) {
    debug_harness::http::request request;
    std::string error;
    const std::string raw = "POST /script HTTP/1.0\r\nContent-Length: 11\r\n\r\nPrint(\"hi\");";
    CHECK(debug_harness::http::parse_request(raw, request, error));
    CHECK_STR_EQ(request.method, "POST");
    CHECK_STR_EQ(request.body, "Print(\"hi\");");
}

TEST(parse_request_rejects_a_malformed_request_line) {
    debug_harness::http::request request;
    std::string error;
    CHECK(!debug_harness::http::parse_request("GARBAGE\r\n\r\n", request, error));
    CHECK(!debug_harness::http::parse_request("", request, error));
    CHECK(!debug_harness::http::parse_request("GET\r\n\r\n", request, error));
}

TEST(parse_request_rejects_a_path_that_does_not_start_with_slash) {
    debug_harness::http::request request;
    std::string error;
    CHECK(!debug_harness::http::parse_request("GET ping HTTP/1.0\r\n\r\n", request, error));
}

TEST(request_get_u64_accepts_hex_and_decimal) {
    debug_harness::http::request request;
    std::string error;
    CHECK(debug_harness::http::parse_request("GET /x?a=0x200&b=64&c=zz HTTP/1.0\r\n\r\n", request, error));

    uint64_t value = 0;
    CHECK(request.get_u64("a", value));
    CHECK_EQ(value, static_cast<uint64_t>(0x200));
    CHECK(request.get_u64("b", value));
    CHECK_EQ(value, static_cast<uint64_t>(64));
    CHECK(!request.get_u64("c", value));
    CHECK(!request.get_u64("missing", value));
}

TEST(request_get_bool_understands_the_usual_spellings) {
    debug_harness::http::request request;
    std::string error;
    CHECK(debug_harness::http::parse_request("GET /x?a=1&b=true&c=0&d=false&e=yes HTTP/1.0\r\n\r\n", request, error));
    CHECK(request.get_bool("a", false));
    CHECK(request.get_bool("b", false));
    CHECK(!request.get_bool("c", true));
    CHECK(!request.get_bool("d", true));
    CHECK(request.get_bool("e", false));
    CHECK(request.get_bool("missing", true));
    CHECK(!request.get_bool("missing", false));
}

TEST(header_end_and_content_length_find_the_body) {
    const std::string raw = "POST /x HTTP/1.0\r\nContent-Length: 4\r\n\r\nabcd";
    CHECK_EQ(debug_harness::http::header_end(raw), raw.find("\r\n\r\n") + 4);
    CHECK_EQ(debug_harness::http::content_length(raw), static_cast<size_t>(4));
}

TEST(content_length_is_case_insensitive_and_defaults_to_zero) {
    CHECK_EQ(debug_harness::http::content_length("POST /x HTTP/1.0\r\ncontent-length: 7\r\n\r\n"), static_cast<size_t>(7));
    CHECK_EQ(debug_harness::http::content_length("GET /x HTTP/1.0\r\n\r\n"), static_cast<size_t>(0));
}

TEST(header_end_returns_npos_when_headers_are_incomplete) {
    CHECK(debug_harness::http::header_end("GET /x HTTP/1.0\r\n") == std::string::npos);
}

TEST(build_response_emits_status_headers_and_body) {
    const auto response = debug_harness::http::build_response(200, "application/json", "{\"ok\":true}");
    CHECK(response.find("HTTP/1.0 200 OK\r\n") == 0);
    CHECK(response.find("Content-Type: application/json\r\n") != std::string::npos);
    CHECK(response.find("Content-Length: 11\r\n") != std::string::npos);
    CHECK(response.find("Connection: close\r\n") != std::string::npos);
    CHECK(response.find("\r\n\r\n{\"ok\":true}") != std::string::npos);
}

TEST(build_response_names_the_status_codes_we_use) {
    CHECK(debug_harness::http::build_response(400, "text/plain", "").find("400 Bad Request") != std::string::npos);
    CHECK(debug_harness::http::build_response(403, "text/plain", "").find("403 Forbidden") != std::string::npos);
    CHECK(debug_harness::http::build_response(404, "text/plain", "").find("404 Not Found") != std::string::npos);
    CHECK(debug_harness::http::build_response(500, "text/plain", "").find("500 Internal Server Error") != std::string::npos);
    CHECK(debug_harness::http::build_response(504, "text/plain", "").find("504 Gateway Timeout") != std::string::npos);
}

TEST(json_escape_handles_quotes_backslashes_and_controls) {
    CHECK_STR_EQ(debug_harness::json::escape("a\"b"), "a\\\"b");
    CHECK_STR_EQ(debug_harness::json::escape("a\\b"), "a\\\\b");
    CHECK_STR_EQ(debug_harness::json::escape("a\nb"), "a\\nb");
    CHECK_STR_EQ(debug_harness::json::escape("a\tb"), "a\\tb");
    CHECK_STR_EQ(debug_harness::json::escape(std::string("a\x01"
                                                 "b")),
                 "a\\u0001b");
}

TEST(json_writer_emits_a_flat_object) {
    debug_harness::json::writer writer;
    writer.begin_object().key("ok").boolean(true).key("name").str("world").key("value").u64(64).end_object();
    CHECK_STR_EQ(writer.take(), "{\"ok\":true,\"name\":\"world\",\"value\":64}");
}

TEST(json_writer_emits_hex_as_a_string) {
    debug_harness::json::writer writer;
    writer.begin_object().key("va").hex(0x7FF6ABCD1234ull).end_object();
    CHECK_STR_EQ(writer.take(), "{\"va\":\"0x7FF6ABCD1234\"}");
}

TEST(json_writer_emits_nested_arrays_of_objects) {
    debug_harness::json::writer writer;
    writer.begin_object()
        .key("steps")
        .begin_array()
        .begin_object()
        .key("i")
        .u64(0)
        .end_object()
        .begin_object()
        .key("i")
        .u64(1)
        .end_object()
        .end_array()
        .end_object();
    CHECK_STR_EQ(writer.take(), "{\"steps\":[{\"i\":0},{\"i\":1}]}");
}

TEST(json_writer_emits_null_and_numbers) {
    debug_harness::json::writer writer;
    writer.begin_object().key("a").null().key("b").num(1.5).key("c").i64(-7).end_object();
    CHECK_STR_EQ(writer.take(), "{\"a\":null,\"b\":1.5,\"c\":-7}");
}

TEST(json_writer_emits_an_empty_object_and_array) {
    debug_harness::json::writer object;
    object.begin_object().end_object();
    CHECK_STR_EQ(object.take(), "{}");

    debug_harness::json::writer array;
    array.begin_array().end_array();
    CHECK_STR_EQ(array.take(), "[]");
}
