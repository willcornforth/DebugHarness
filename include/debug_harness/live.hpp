#pragma once

#include <cstdint>
#include <string>
#include <vector>

#include "debug_harness/expr.hpp"
#include "debug_harness/harness.hpp"
#include "debug_harness/mem.hpp"

// Binds the pure debug core to the running process.
//
// Which module ida:/rva:/@base refer to comes from host_config::module_name
// (nullptr = the main executable). Named roots and symbols come from the host's
// host_config callbacks; the library itself only knows @base. That keeps this
// translation unit free of any host-specific types, so the host tests compile it and
// the ida:/rva:/va: translation arithmetic is unit tested.
namespace debug_harness::live {

    // Live load address of the configured module. 0 when it is not loaded.
    uint64_t module_base();

    // Link-time IMAGE_OPTIONAL_HEADER64::ImageBase. The loader does not rewrite this
    // field when it relocates the image, so the mapped headers still carry it.
    uint64_t module_preferred_base();

    size_t module_image_size();
    std::string module_name();

    // The built-in @base first, then whatever host_config::enumerate_roots returns.
    std::vector<root_entry> roots();

    // The `expr::env` the parser runs against: built-in @base, host roots and symbols,
    // guarded reads.
    const debug_harness::expr::env& env();

    struct addr_info {
        uint64_t va = 0;
        uint64_t rva = 0; // 0 when not in the configured module
        uint64_t ida = 0; // 0 when not in the configured module
        bool in_module = false;
        debug_harness::mem::region_info region;
    };

    // Translate one live address into all three coordinate systems, with its region.
    addr_info describe(uint64_t va);
}
