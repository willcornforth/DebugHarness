#pragma once

#include <cstdint>
#include <string>
#include <vector>

// The debug harness address grammar.
//
//   root      := "va:" hex | "rva:" hex | "ida:" hex | "@" identifier
//   suffix    := "+" addend              -- add, no dereference
//              | "[" [ "+" addend ] "]"  -- add then dereference a qword
//   addend    := hex | qualified-symbol-name
//   hex       := "0x" hexdigits
//
// Suffixes apply left to right. Example, a double dereference through two host-named
// offsets followed by a plain field offset:
//
//   @local.player[+Player::OFF_INVENTORY][+Inventory::OFF_FIRST_SLOT][]+0x3C
//
// This translation unit has no Windows and no host dependency: everything it needs
// arrives through `env`. That is what makes it unit-testable on the host.
namespace debug_harness::expr {

    // Supplied by the caller. debug_harness::live implements this against the running process;
    // the host tests implement it over std::map.
    struct env {
        virtual ~env() = default;

        // Live load address of the configured module.
        virtual uint64_t module_base() const = 0;

        // Link-time preferred base from IMAGE_OPTIONAL_HEADER64::ImageBase.
        virtual uint64_t preferred_base() const = 0;

        // Resolve "@name". False when the name is unknown. `out_note` is free-form
        // annotation shown in the step trace.
        virtual bool root(const std::string& name, uint64_t& out_value, std::string& out_note) const = 0;

        // Resolve a named addend, e.g. "Player::OFF_INVENTORY".
        virtual bool symbol(const std::string& qualified, uint64_t& out_value) const = 0;

        // Read a qword. False when the address is not safely readable.
        virtual bool read_u64(uint64_t address, uint64_t& out_value, std::string& out_note) const = 0;
    };

    struct step {
        std::string label;    // "@local.player", "+0x130", "[+0x130]"
        uint64_t address = 0; // address this step produced, or read from when deref
        uint64_t value = 0;   // dereferenced value; equals `address` when !deref
        bool deref = false;
        bool ok = false;
        std::string note; // env annotation, or the failure reason
    };

    struct result {
        bool ok = false;
        std::string error;    // empty when ok
        size_t error_at = 0;   // byte offset into the expression
        uint64_t address = 0; // final resolved address
        std::vector<step> steps;
    };

    // Evaluate an expression.
    //
    // On failure `steps` still holds every step that did run, so a caller such as
    // GET /chain can show exactly which link in a pointer chain broke. Always check
    // `ok` before trusting `address`.
    result evaluate(const std::string& expression, const env& env);
}
