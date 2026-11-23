#include "debug_harness/live.hpp"

#include <Windows.h>

#include <mutex>

namespace {

    struct module_info {
        uint64_t base = 0;
        uint64_t preferred_base = 0;
        size_t image_size = 0;
        std::string name;
    };

    module_info build(const char* module_name) {
        module_info built;
        built.base = reinterpret_cast<uint64_t>(GetModuleHandleA(module_name));
        if (!built.base) return built;

        const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(built.base);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return built;

        const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS64*>(built.base + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return built;

        built.preferred_base = nt_headers->OptionalHeader.ImageBase;
        built.image_size = nt_headers->OptionalHeader.SizeOfImage;

        char path[MAX_PATH] = {};
        if (GetModuleFileNameA(reinterpret_cast<HMODULE>(built.base), path, MAX_PATH)) {
            const std::string full(path);
            const size_t slash = full.find_last_of("\\/");
            built.name = slash == std::string::npos ? full : full.substr(slash + 1);
        }
        return built;
    }

    // Cached per configured module name. configure() may swap the name, so the cache
    // is keyed on it rather than built once; a module that was not loaded yet (base 0)
    // is retried on the next call instead of being cached as absent forever.
    module_info current_module() {
        static std::mutex mutex;
        static bool cached = false;
        static std::string cached_key;
        static module_info cached_info;

        const char* module_name = debug_harness::config().module_name;
        const std::string key = module_name ? module_name : "";

        std::lock_guard lock(mutex);
        if (!cached || key != cached_key || cached_info.base == 0) {
            cached_info = build(module_name);
            cached_key = key;
            cached = true;
        }
        return cached_info;
    }

    bool built_in_root(const std::string& name, uint64_t& out_value, std::string& out_note, bool& out_handled) {
        out_handled = false;
        if (name != "base") return false;
        out_handled = true;
        const auto module = current_module();
        if (module.base == 0) {
            out_note = "module unavailable";
            return false;
        }
        out_value = module.base;
        out_note = module.name;
        return true;
    }

    struct live_env : debug_harness::expr::env {
        uint64_t module_base() const override { return current_module().base; }
        uint64_t preferred_base() const override { return current_module().preferred_base; }

        bool root(const std::string& name, uint64_t& out_value, std::string& out_note) const override {
            bool handled = false;
            const bool resolved = built_in_root(name, out_value, out_note, handled);
            if (handled) return resolved;

            const auto& resolver = debug_harness::config().resolve_root;
            if (!resolver) {
                out_note = "no such root (host provides no root resolver)";
                return false;
            }
            return resolver(name, out_value, out_note);
        }

        bool symbol(const std::string& qualified, uint64_t& out_value) const override {
            const auto& resolver = debug_harness::config().resolve_symbol;
            if (!resolver) return false;
            return resolver(qualified, out_value);
        }

        bool read_u64(uint64_t address, uint64_t& out_value, std::string& out_note) const override {
            const auto region = debug_harness::mem::query(address);
            if (!debug_harness::mem::safe_read_u64(address, out_value)) {
                out_note = region.valid ? "not readable" : "not committed";
                return false;
            }
            // Annotate where the value came from; the chain trace shows this per link.
            if (!region.module_name.empty()) {
                out_note = region.module_name;
                if (!region.section_name.empty()) out_note += " " + region.section_name;
            } else {
                out_note = "heap";
            }
            return true;
        }
    };
}

namespace debug_harness::live {

    uint64_t module_base() {
        return current_module().base;
    }
    uint64_t module_preferred_base() {
        return current_module().preferred_base;
    }
    size_t module_image_size() {
        return current_module().image_size;
    }
    std::string module_name() {
        return current_module().name;
    }

    std::vector<root_entry> roots() {
        std::vector<root_entry> entries;

        root_entry base;
        base.name = "base";
        bool handled = false;
        base.valid = built_in_root("base", base.value, base.note, handled);
        if (!base.valid) base.value = 0;
        entries.push_back(base);

        const auto& enumerator = config().enumerate_roots;
        if (enumerator) {
            for (auto& entry : enumerator()) {
                if (entry.name == "base") continue; // the built-in wins; never list it twice
                entries.push_back(std::move(entry));
            }
        }
        return entries;
    }

    const debug_harness::expr::env& env() {
        static const live_env env;
        return env;
    }

    addr_info describe(uint64_t va) {
        addr_info info;
        info.va = va;
        info.region = debug_harness::mem::query(va);

        const auto module = current_module();
        if (module.base != 0 && va >= module.base && va < module.base + module.image_size) {
            info.in_module = true;
            info.rva = va - module.base;
            info.ida = module.preferred_base + info.rva;
        }
        return info;
    }
}
