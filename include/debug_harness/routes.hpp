#pragma once

#include <string>
#include <vector>

#include "debug_harness/http.hpp"

// Request routing for the loopback listener.
//
// Built-in endpoints (all GET unless noted; every body is JSON):
//   /ping    module, base, port, uptime, write-arm state
//   /routes  every built-in and host-registered route
//   /roots   @base plus the host's roots
//   /addr    ?e=     va/rva/ida, module, section, protection
//   /region  ?e=     VirtualQuery view of the address
//   /read    ?e= [&n=] [&as=hex|u8..u64|i8..i64|f32|f64|ptr|cstr|wstr]
//   /chain   ?e=     per-step trace; a broken chain still answers 200 with ok:false
//   /struct  ?e= [&n=]       qword-by-qword classification
//   /vtable  ?e= [&count=]   slots of the object's vtable
//   /scan    ?p= [&max=]     IDA-style pattern over the configured module
//   /offsets [?filter=]      host_config::enumerate_symbols
//   /log     [?since=]       host_config::log_entries; 404 when the host provides none
//   /write   POST ?e=&v= [&as=] [&force=1]  only while mem::arm_writes is in effect,
//                                           which is never reachable over HTTP
//
// Route precedence: built-ins are matched first, then routes added with
// debug_harness::register_route. A host route registered on a built-in path is
// therefore SHADOWED -- it is kept in the registry and listed by /routes with
// "shadowed":true, but never invoked. That keeps /write's arm gate and the other
// safety-relevant endpoints from being replaced by accident; a host wanting different
// behaviour registers its own path.
namespace debug_harness::routes {

    // Route one request. Returns the JSON body and sets out_status. Never throws:
    // an exception escaping any handler, built-in or registered, becomes HTTP 500.
    std::string dispatch(const http::request& request, int& out_status);

    // {"ok":false,"error":"..."}
    std::string error_body(const std::string& message);

    struct route_info {
        std::string path;
        std::string description;
        bool built_in = false;
        bool shadowed = false; // a registered route hidden behind a built-in of the same path
    };

    // Built-ins in table order, then registered routes sorted by path.
    std::vector<route_info> list();
}
