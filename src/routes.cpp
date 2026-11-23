#include "debug_harness/routes.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <iterator>
#include <stdexcept>
#include <string>
#include <vector>

#include "debug_harness/expr.hpp"
#include "debug_harness/harness.hpp"
#include "debug_harness/live.hpp"
#include "debug_harness/mem.hpp"
#include "debug_harness/scan.hpp"
#include "debug_harness/server.hpp"
#include "internal/route_registry.hpp"

namespace debug_harness::routes {

    std::string error_body(const std::string& message) {
        json::writer writer;
        writer.begin_object().key("ok").boolean(false).key("error").str(message).end_object();
        return writer.take();
    }

    namespace {

        // --- shared helpers -------------------------------------------------

        // Evaluate the expression carried by query parameter `key`.
        bool resolve(const http::request& request, const char* key, expr::result& out, std::string& out_error) {
            if (!request.has(key)) {
                out_error = std::string("missing required parameter '") + key + "'";
                return false;
            }
            out = expr::evaluate(request.get(key), live::env());
            if (!out.ok) {
                out_error = out.error;
                return false;
            }
            return true;
        }

        // va / rva / ida / module / section / protection for one address.
        void write_addr(json::writer& writer, uint64_t va) {
            const auto info = live::describe(va);
            writer.key("va").hex(info.va);
            if (info.in_module) {
                writer.key("rva").hex(info.rva);
                writer.key("ida").hex(info.ida);
            } else {
                writer.key("rva").null();
                writer.key("ida").null();
            }
            writer.key("module").str(info.region.module_name);
            writer.key("section").str(info.region.section_name);
            writer.key("readable").boolean(info.region.readable);
            writer.key("writable").boolean(info.region.writable);
            writer.key("executable").boolean(info.region.executable);
        }

        // The per-step trace, shared by /chain and anything else that wants to show
        // how it reached an address.
        void write_steps(json::writer& writer, const expr::result& result) {
            writer.key("steps").begin_array();
            for (const auto& step : result.steps) {
                writer.begin_object()
                    .key("label")
                    .str(step.label)
                    .key("address")
                    .hex(step.address)
                    .key("value")
                    .hex(step.value)
                    .key("deref")
                    .boolean(step.deref)
                    .key("ok")
                    .boolean(step.ok)
                    .key("note")
                    .str(step.note)
                    .end_object();
            }
            writer.end_array();
        }

        std::string hex_bytes(const std::vector<uint8_t>& bytes) {
            std::string out;
            out.reserve(bytes.size() * 3);
            for (size_t i = 0; i < bytes.size(); ++i) {
                if (i) out.push_back(' ');
                std::format_to(std::back_inserter(out), "{:02X}", bytes[i]);
            }
            return out;
        }

        // --- handlers -------------------------------------------------------

        std::string ping(const http::request&, int&) {
            const auto stats = get_stats();
            const uint64_t uptime_ms = stats.started_tick_ms ? (GetTickCount64() - stats.started_tick_ms) : 0;

            json::writer writer;
            writer.begin_object()
                .key("ok")
                .boolean(true)
                .key("module")
                .str(live::module_name())
                .key("base")
                .hex(live::module_base())
                .key("preferredBase")
                .hex(live::module_preferred_base())
                .key("imageSize")
                .hex(live::module_image_size())
                .key("libBuild")
                .str(std::string(__DATE__) + " " + __TIME__)
                .key("port")
                .u64(port())
                .key("uptimeMs")
                .u64(uptime_ms)
                .key("requestCount")
                .u64(stats.request_count)
                .key("writesArmed")
                .boolean(mem::writes_armed())
                .key("writeArmSecondsLeft")
                .u64(mem::write_arm_seconds_left())
                .end_object();
            return writer.take();
        }

        std::string routes_listing(const http::request&, int&) {
            json::writer writer;
            writer.begin_object().key("ok").boolean(true).key("routes").begin_array();
            for (const auto& route : list()) {
                writer.begin_object()
                    .key("path")
                    .str(route.path)
                    .key("description")
                    .str(route.description)
                    .key("builtIn")
                    .boolean(route.built_in)
                    .key("shadowed")
                    .boolean(route.shadowed)
                    .end_object();
            }
            writer.end_array().end_object();
            return writer.take();
        }

        std::string roots(const http::request&, int&) {
            json::writer writer;
            writer.begin_object().key("ok").boolean(true).key("roots").begin_array();
            for (const auto& root : live::roots()) {
                writer.begin_object().key("name").str("@" + root.name).key("valid").boolean(root.valid);
                if (root.valid)
                    writer.key("value").hex(root.value);
                else
                    writer.key("value").null();
                writer.key("note").str(root.note).end_object();
            }
            writer.end_array().end_object();
            return writer.take();
        }

        std::string addr(const http::request& request, int& status) {
            expr::result resolved;
            std::string error;
            if (!resolve(request, "e", resolved, error)) {
                status = 400;
                return error_body(error);
            }

            json::writer writer;
            writer.begin_object().key("ok").boolean(true);
            write_addr(writer, resolved.address);
            writer.end_object();
            return writer.take();
        }

        std::string region(const http::request& request, int& status) {
            expr::result resolved;
            std::string error;
            if (!resolve(request, "e", resolved, error)) {
                status = 400;
                return error_body(error);
            }

            const auto info = mem::query(resolved.address);
            json::writer writer;
            writer.begin_object()
                .key("ok")
                .boolean(true)
                .key("address")
                .hex(resolved.address)
                .key("valid")
                .boolean(info.valid)
                .key("allocationBase")
                .hex(info.allocation_base)
                .key("regionBase")
                .hex(info.region_base)
                .key("regionSize")
                .hex(info.region_size)
                .key("protect")
                .hex(info.protect)
                .key("state")
                .hex(info.state)
                .key("type")
                .hex(info.type)
                .key("readable")
                .boolean(info.readable)
                .key("writable")
                .boolean(info.writable)
                .key("executable")
                .boolean(info.executable)
                .key("guarded")
                .boolean(info.guarded)
                .key("module")
                .str(info.module_name)
                .key("section")
                .str(info.section_name)
                .key("moduleBase")
                .hex(info.module_base)
                .end_object();
            return writer.take();
        }

        template <typename T>
        T load(const uint8_t* raw) {
            T value;
            std::memcpy(&value, raw, sizeof(T));
            return value;
        }

        std::string read(const http::request& request, int& status) {
            expr::result resolved;
            std::string error;
            if (!resolve(request, "e", resolved, error)) {
                status = 400;
                return error_body(error);
            }

            const std::string as = request.get("as", "hex");

            uint64_t length = 0;
            if (!request.get_u64("n", length)) length = 16;
            if (length == 0 || length > mem::max_read_bytes) {
                status = 400;
                return error_body("n must be between 1 and " + std::to_string(mem::max_read_bytes));
            }

            json::writer writer;
            writer.begin_object().key("ok").boolean(true);
            write_addr(writer, resolved.address);
            writer.key("as").str(as);

            // String forms read their own way; everything else is a byte read plus an
            // interpretation of the first sizeof(T) bytes.
            if (as == "cstr" || as == "wstr") {
                std::string text;
                const bool was_read =
                    (as == "cstr") ? mem::safe_read_c_string(resolved.address, static_cast<size_t>(length), text)
                                   : mem::safe_read_w_string(resolved.address, static_cast<size_t>(length), text);
                writer.key("read").boolean(was_read);
                if (was_read)
                    writer.key("value").str(text);
                else
                    writer.key("value").null();
                writer.end_object();
                return writer.take();
            }

            std::vector<uint8_t> bytes(static_cast<size_t>(length));
            if (!mem::safe_read(resolved.address, bytes.data(), bytes.size())) {
                writer.key("read").boolean(false).key("error").str("address is not safely readable").end_object();
                return writer.take();
            }

            writer.key("read").boolean(true).key("hex").str(hex_bytes(bytes));

            const auto* raw = bytes.data();
            const size_t size = bytes.size();
            const auto fits = [&](size_t need) { return size >= need; };

            if (as == "u8" && fits(1)) {
                writer.key("value").u64(load<uint8_t>(raw));
            } else if (as == "u16" && fits(2)) {
                writer.key("value").u64(load<uint16_t>(raw));
            } else if (as == "u32" && fits(4)) {
                writer.key("value").u64(load<uint32_t>(raw));
            } else if (as == "u64" && fits(8)) {
                writer.key("value").u64(load<uint64_t>(raw));
            } else if (as == "i8" && fits(1)) {
                writer.key("value").i64(load<int8_t>(raw));
            } else if (as == "i16" && fits(2)) {
                writer.key("value").i64(load<int16_t>(raw));
            } else if (as == "i32" && fits(4)) {
                writer.key("value").i64(load<int32_t>(raw));
            } else if (as == "i64" && fits(8)) {
                writer.key("value").i64(load<int64_t>(raw));
            } else if (as == "f32" && fits(4)) {
                writer.key("value").num(load<float>(raw));
            } else if (as == "f64" && fits(8)) {
                writer.key("value").num(load<double>(raw));
            } else if (as == "ptr" && fits(8)) {
                const auto value = load<uint64_t>(raw);
                writer.key("value").hex(value);
                writer.key("points_to").str(mem::classify(value).text);
            } else if (as != "hex") {
                writer.key("value").null().key("warning").str("unknown or undersized 'as' type; returning hex only");
            }

            writer.end_object();
            return writer.take();
        }

        std::string chain(const http::request& request, int& status) {
            if (!request.has("e")) {
                status = 400;
                return error_body("missing required parameter 'e'");
            }

            // Evaluate directly, not through resolve: a broken chain is exactly what
            // this endpoint exists to show, so the partial trace must survive.
            const auto result = expr::evaluate(request.get("e"), live::env());

            json::writer writer;
            writer.begin_object().key("ok").boolean(result.ok).key("expression").str(request.get("e"));

            if (!result.ok) {
                writer.key("error").str(result.error).key("errorAt").u64(result.error_at).key("result").null();
            } else {
                writer.key("result").hex(result.address);
                writer.key("resolved").begin_object();
                write_addr(writer, result.address);
                writer.end_object();
            }

            write_steps(writer, result);
            writer.end_object();
            return writer.take();
        }

        std::string structure(const http::request& request, int& status) {
            expr::result resolved;
            std::string error;
            if (!resolve(request, "e", resolved, error)) {
                status = 400;
                return error_body(error);
            }

            uint64_t length = 0;
            if (!request.get_u64("n", length)) length = 0x100;
            if (length == 0 || length > 0x1000) {
                status = 400;
                return error_body("n must be between 1 and 0x1000");
            }
            length &= ~static_cast<uint64_t>(7); // whole qwords only
            if (length == 0) length = 8;

            json::writer writer;
            writer.begin_object().key("ok").boolean(true);
            write_addr(writer, resolved.address);
            writer.key("length").hex(length);
            writer.key("note").str("classification is a heuristic, not ground truth");
            writer.key("fields").begin_array();

            for (uint64_t offset = 0; offset < length; offset += 8) {
                const uint64_t at = resolved.address + offset;
                writer.begin_object().key("offset").hex(offset);

                uint64_t value = 0;
                if (!mem::safe_read_u64(at, value)) {
                    writer.key("readable").boolean(false).key("value").null().key("kind").str("unreadable").end_object();
                    continue;
                }

                const auto classification = mem::classify(value);
                writer.key("readable").boolean(true).key("value").hex(value).key("kind").str(classification.text);
                if (classification.vtable_slots) writer.key("vtableSlots").u64(classification.vtable_slots);
                writer.end_object();
            }

            writer.end_array().end_object();
            return writer.take();
        }

        std::string vtable(const http::request& request, int& status) {
            expr::result resolved;
            std::string error;
            if (!resolve(request, "e", resolved, error)) {
                status = 400;
                return error_body(error);
            }

            uint64_t count = 0;
            if (!request.get_u64("count", count)) count = 64;
            if (count == 0 || count > 512) {
                status = 400;
                return error_body("count must be between 1 and 512");
            }

            // The expression names the object; slot 0 of its vtable lives at *object.
            // Pass a vtable address directly by appending [] yourself.
            uint64_t table = 0;
            if (!mem::safe_read_u64(resolved.address, table)) {
                json::writer writer;
                writer.begin_object()
                    .key("ok")
                    .boolean(false)
                    .key("error")
                    .str("could not read a vtable pointer at the object address")
                    .key("object")
                    .hex(resolved.address)
                    .end_object();
                return writer.take();
            }

            json::writer writer;
            writer.begin_object().key("ok").boolean(true).key("object").hex(resolved.address).key("vtable").begin_object();
            write_addr(writer, table);
            writer.end_object();
            writer.key("slots").begin_array();

            uint64_t executable_slots = 0;
            for (uint64_t index = 0; index < count; ++index) {
                const uint64_t slot_address = table + index * 8;
                uint64_t target = 0;
                if (!mem::safe_read_u64(slot_address, target)) break;

                const auto info = live::describe(target);
                if (!info.region.valid || !info.region.executable) break; // past the end of the table

                ++executable_slots;
                writer.begin_object()
                    .key("index")
                    .u64(index)
                    .key("indexHex")
                    .hex(index * 8) // the "[rax+0xC0]" form seen in IDA
                    .key("va")
                    .hex(target);
                if (info.in_module) {
                    writer.key("rva").hex(info.rva);
                    writer.key("ida").hex(info.ida);
                } else {
                    writer.key("rva").null().key("ida").null();
                }
                writer.key("module")
                    .str(info.region.module_name)
                    .key("section")
                    .str(info.region.section_name)
                    .end_object();
            }

            writer.end_array().key("slotCount").u64(executable_slots).end_object();
            return writer.take();
        }

        std::string scan_route(const http::request& request, int& status) {
            if (!request.has("p")) {
                status = 400;
                return error_body("missing required parameter 'p' (the byte pattern)");
            }
            const std::string pattern = request.get("p");

            uint64_t max_hits = 0;
            if (!request.get_u64("max", max_hits)) max_hits = 8;
            if (max_hits == 0 || max_hits > 256) max_hits = 8;

            const auto result = scan::find_all(pattern.c_str(), static_cast<size_t>(max_hits));
            if (!result.pattern_valid) {
                status = 400;
                return error_body("could not parse the pattern; expected IDA style, "
                                  "e.g. '48 8B D9 48 8B 0D ? ? ? ?'");
            }

            json::writer writer;
            writer.begin_object()
                .key("ok")
                .boolean(true)
                .key("pattern")
                .str(pattern)
                .key("totalHits")
                .u64(result.total_hits)
                .key("unique")
                .boolean(result.total_hits == 1)
                .key("truncated")
                .boolean(result.total_hits > result.hits.size())
                .key("hits")
                .begin_array();

            for (const auto hit : result.hits) {
                writer.begin_object();
                write_addr(writer, hit);
                writer.end_object();
            }

            writer.end_array().end_object();
            return writer.take();
        }

        std::string offsets(const http::request& request, int&) {
            const std::string filter = request.get("filter");
            const auto& enumerate = config().enumerate_symbols;

            json::writer writer;
            writer.begin_object().key("ok").boolean(true);
            if (!enumerate) writer.key("note").str("the host provides no symbol enumerator");
            writer.key("offsets").begin_array();

            if (enumerate) {
                for (const auto& entry : enumerate()) {
                    const std::string qualified = entry.ns.empty() ? entry.name : entry.ns + "::" + entry.name;
                    if (!filter.empty() && qualified.find(filter) == std::string::npos) continue;

                    writer.begin_object()
                        .key("namespace")
                        .str(entry.ns)
                        .key("name")
                        .str(entry.name)
                        .key("qualified")
                        .str(qualified)
                        .key("value")
                        .hex(entry.value)
                        .end_object();
                }
            }

            writer.end_array().end_object();
            return writer.take();
        }

        const char* level_text(log_level level) {
            switch (level) {
            case log_level::debug:
                return "DEBUG";
            case log_level::warning:
                return "WARN";
            case log_level::error:
                return "ERROR";
            case log_level::info:
            default:
                return "INFO";
            }
        }

        std::string log_route(const http::request& request, int& status) {
            const auto& provider = config().log_entries;
            if (!provider) {
                status = 404;
                return error_body("not provided by host");
            }

            uint64_t since = 0;
            if (!request.get_u64("since", since)) since = 0;

            // The provider runs on the server thread; the host is responsible for
            // returning a snapshot taken under its own lock. A host that trims aged
            // entries makes `since` a best-effort cursor, not a stable one.
            const auto entries = provider();

            json::writer writer;
            writer.begin_object().key("ok").boolean(true).key("total").u64(entries.size()).key("entries").begin_array();

            for (const auto& entry : entries) {
                if (entry.index < since) continue;
                writer.begin_object()
                    .key("index")
                    .u64(entry.index)
                    .key("level")
                    .str(level_text(entry.level))
                    .key("message")
                    .str(entry.text)
                    .key("timestampMs")
                    .u64(entry.timestamp_ms);
                if (!entry.trace.empty()) writer.key("trace").str(entry.trace);
                writer.end_object();
            }

            writer.end_array().end_object();
            return writer.take();
        }

        // Encode `text` as `as` into raw bytes. False with out_error set on a bad type
        // or an unparseable value.
        bool encode_value(const std::string& as, const std::string& text, std::vector<uint8_t>& out,
                          std::string& out_error) {
            out.clear();

            const auto parse_u64 = [&](uint64_t& value) {
                size_t index = 0;
                int base = 10;
                if (text.size() > 2 && text[0] == '0' && (text[1] == 'x' || text[1] == 'X')) {
                    index = 2;
                    base = 16;
                }
                uint64_t accumulated = 0;
                size_t digits = 0;
                for (; index < text.size(); ++index) {
                    const char ch = text[index];
                    int digit = -1;
                    if (ch >= '0' && ch <= '9')
                        digit = ch - '0';
                    else if (ch >= 'a' && ch <= 'f')
                        digit = ch - 'a' + 10;
                    else if (ch >= 'A' && ch <= 'F')
                        digit = ch - 'A' + 10;
                    if (digit < 0 || digit >= base) return false;
                    accumulated = accumulated * static_cast<uint64_t>(base) + static_cast<uint64_t>(digit);
                    ++digits;
                }
                if (digits == 0) return false;
                value = accumulated;
                return true;
            };

            const auto assign = [&](const void* source, size_t size) {
                const auto* raw = static_cast<const uint8_t*>(source);
                out.assign(raw, raw + size);
            };

            if (as == "hex") {
                // "DE AD BE EF" or "DEADBEEF"
                std::vector<scan::pattern_byte> parsed;
                if (!scan::parse_pattern(text.c_str(), parsed)) {
                    out_error = "could not parse hex bytes";
                    return false;
                }
                for (const auto& byte : parsed) {
                    if (byte.is_wildcard) {
                        out_error = "wildcards are not allowed in a write payload";
                        return false;
                    }
                    out.push_back(byte.value);
                }
                return !out.empty();
            }

            const auto integer_of_width = [&](size_t width) {
                uint64_t integer = 0;
                if (!parse_u64(integer)) {
                    out_error = "bad integer";
                    return false;
                }
                // Little-endian truncation to the requested width.
                assign(&integer, width);
                return true;
            };

            if (as == "u8" || as == "i8") return integer_of_width(1);
            if (as == "u16" || as == "i16") return integer_of_width(2);
            if (as == "u32" || as == "i32") return integer_of_width(4);
            if (as == "u64" || as == "i64") return integer_of_width(8);

            if (as == "f32") {
                try {
                    const float v = std::stof(text);
                    assign(&v, 4);
                    return true;
                } catch (...) {
                    out_error = "bad float";
                    return false;
                }
            }
            if (as == "f64") {
                try {
                    const double v = std::stod(text);
                    assign(&v, 8);
                    return true;
                } catch (...) {
                    out_error = "bad double";
                    return false;
                }
            }

            out_error = "unknown type '" + as + "'; expected hex, u8..u64, i8..i64, f32 or f64";
            return false;
        }

        std::string write(const http::request& request, int& status) {
            if (request.method != "POST") {
                status = 400;
                return error_body("/write requires POST");
            }

            // Checked before anything else: arming is only possible in-process
            // (mem::arm_writes), so a stray URL can never modify memory.
            if (!mem::writes_armed()) {
                status = 403;
                return error_body("writes are not armed; arm them in-process "
                                  "(mem::arm_writes, e.g. from the Debug Harness panel)");
            }

            expr::result resolved;
            std::string error;
            if (!resolve(request, "e", resolved, error)) {
                status = 400;
                return error_body(error);
            }

            if (!request.has("v")) {
                status = 400;
                return error_body("missing required parameter 'v' (the value to write)");
            }

            const std::string as = request.get("as", "hex");
            std::vector<uint8_t> payload;
            if (!encode_value(as, request.get("v"), payload, error)) {
                status = 400;
                return error_body(error);
            }
            if (payload.empty() || payload.size() > mem::max_write_bytes) {
                status = 400;
                return error_body("payload must be 1 to " + std::to_string(mem::max_write_bytes) + " bytes");
            }

            const bool force = request.get_bool("force", false);

            size_t undo_index = 0;
            std::string write_error;
            if (!mem::safe_write(resolved.address, payload.data(), payload.size(), force, "http", undo_index,
                                 write_error)) {
                // A refused write is a result, not a transport error.
                json::writer writer;
                writer.begin_object()
                    .key("ok")
                    .boolean(false)
                    .key("error")
                    .str(write_error)
                    .key("address")
                    .hex(resolved.address)
                    .end_object();
                return writer.take();
            }

            const auto undo = mem::undo_log();
            json::writer writer;
            writer.begin_object().key("ok").boolean(true);
            write_addr(writer, resolved.address);
            writer.key("as")
                .str(as)
                .key("bytesWritten")
                .u64(payload.size())
                .key("newBytes")
                .str(hex_bytes(payload))
                .key("oldBytes")
                .str(undo_index < undo.size() ? hex_bytes(undo[undo_index].old_bytes) : "")
                .key("undoIndex")
                .u64(undo_index)
                .key("forced")
                .boolean(force)
                .key("note")
                .str("revert in-process via mem::revert (e.g. the Debug Harness panel's write log)")
                .end_object();
            return writer.take();
        }

        using built_in_handler = std::string (*)(const http::request&, int&);

        struct built_in {
            const char* path;
            const char* description;
            built_in_handler handler;
        };

        constexpr built_in built_ins[] = {
            {"/ping", "module, base, port, uptime and write-arm state", ping},
            {"/routes", "every built-in and host-registered route", routes_listing},
            {"/roots", "@base plus the host's named roots", roots},
            {"/addr", "?e= -- va/rva/ida, module, section and protection of an address", addr},
            {"/region", "?e= -- VirtualQuery view of an address", region},
            {"/read", "?e= [&n=] [&as=] -- read and interpret bytes", read},
            {"/chain", "?e= -- evaluate an expression with its per-step trace", chain},
            {"/struct", "?e= [&n=] -- qword-by-qword classification", structure},
            {"/vtable", "?e= [&count=] -- the slots of an object's vtable", vtable},
            {"/scan", "?p= [&max=] -- IDA-style pattern scan of the configured module", scan_route},
            {"/offsets", "[?filter=] -- the host's named symbols", offsets},
            {"/log", "[?since=] -- the host's log entries", log_route},
            {"/write", "POST ?e=&v= [&as=] [&force=1] -- only while armed in-process", write},
        };

        const built_in* find_built_in(const std::string& path) {
            for (const auto& entry : built_ins)
                if (path == entry.path) return &entry;
            return nullptr;
        }
    }

    std::vector<route_info> list() {
        std::vector<route_info> out;
        for (const auto& entry : built_ins)
            out.push_back(route_info{entry.path, entry.description, true, false});
        for (const auto& [path, description] : detail::list_routes())
            out.push_back(route_info{path, description, false, find_built_in(path) != nullptr});
        return out;
    }

    std::string dispatch(const http::request& request, int& out_status) {
        out_status = 200;
        try {
            // Built-ins first: a registered route on a built-in path is shadowed (see
            // routes.hpp for why).
            if (const auto* entry = find_built_in(request.path)) return entry->handler(request, out_status);

            route_handler handler;
            if (detail::find_route(request.path, handler)) return handler(request, out_status);

            out_status = 404;
            return error_body("no such endpoint: " + request.path);
        } catch (const std::exception& error) {
            out_status = 500;
            return error_body(std::string("handler threw: ") + error.what());
        } catch (...) {
            out_status = 500;
            return error_body("handler threw an unknown exception");
        }
    }
}
