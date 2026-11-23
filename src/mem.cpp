#include "debug_harness/mem.hpp"

#include <cmath>
#include <cstring>
#include <format>
#include <mutex>

namespace {

    // Leaf function: no C++ objects with destructors, so __try is legal here.
    // MSVC emits C2712 if __try appears in a function requiring object unwinding.
    bool raw_copy(void* destination, const void* source, size_t size) {
        __try {
            memcpy(destination, source, size);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    // Leaf function, same C2712 reasoning as raw_copy.
    bool raw_write(void* destination, const void* source, size_t size) {
        __try {
            memcpy(destination, source, size);
            return true;
        } __except (EXCEPTION_EXECUTE_HANDLER) {
            return false;
        }
    }

    struct write_state {
        std::mutex mutex;
        bool armed = false;
        uint64_t arm_expiry_ms = 0;
        std::vector<debug_harness::mem::write_record> undo_log;
    };

    write_state& writes() {
        static write_state state;
        return state;
    }

    bool protect_allows_read(DWORD protect) {
        const DWORD access = protect & 0xFF;
        switch (access) {
        case PAGE_READONLY:
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            // PAGE_NOACCESS and execute-only PAGE_EXECUTE are not readable.
            return false;
        }
    }

    bool protect_allows_write(DWORD protect) {
        const DWORD access = protect & 0xFF;
        switch (access) {
        case PAGE_READWRITE:
        case PAGE_WRITECOPY:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    bool protect_allows_execute(DWORD protect) {
        const DWORD access = protect & 0xFF;
        switch (access) {
        case PAGE_EXECUTE:
        case PAGE_EXECUTE_READ:
        case PAGE_EXECUTE_READWRITE:
        case PAGE_EXECUTE_WRITECOPY:
            return true;
        default:
            return false;
        }
    }

    std::string hex_string(uint64_t value) {
        return std::format("0x{:X}", value);
    }

    std::string float_string(float value) {
        return std::format("{:g}", static_cast<double>(value));
    }

    // A float we would plausibly find in host data: finite, and either exactly zero
    // or of a sane magnitude. Rejects denormals and astronomically large values,
    // which is what stops arbitrary pointers reading as coordinates.
    bool plausible_float(float value) {
        if (!std::isfinite(value)) return false;
        if (value == 0.0f) return true;
        const float magnitude = std::fabs(value);
        return magnitude >= 1e-4f && magnitude <= 1e7f;
    }

    bool looks_printable(const std::string& text) {
        if (text.size() < 4) return false;
        for (const char ch : text) {
            const auto value = static_cast<unsigned char>(ch);
            if (value < 0x20 || value > 0x7E) return false;
        }
        return true;
    }

    std::string base_name(const std::string& path) {
        const size_t slash = path.find_last_of("\\/");
        return slash == std::string::npos ? path : path.substr(slash + 1);
    }

    // Name of the PE section containing `address`, given its module base.
    std::string section_name_for(uint64_t module_base, uint64_t address) {
        const auto dos_header = reinterpret_cast<const IMAGE_DOS_HEADER*>(module_base);
        if (dos_header->e_magic != IMAGE_DOS_SIGNATURE) return "";

        const auto nt_headers = reinterpret_cast<const IMAGE_NT_HEADERS*>(module_base + dos_header->e_lfanew);
        if (nt_headers->Signature != IMAGE_NT_SIGNATURE) return "";

        const auto rva = static_cast<DWORD>(address - module_base);
        auto section = IMAGE_FIRST_SECTION(nt_headers);

        for (WORD i = 0; i < nt_headers->FileHeader.NumberOfSections; ++i, ++section) {
            const DWORD start = section->VirtualAddress;
            DWORD size = section->Misc.VirtualSize;
            if (size == 0) size = section->SizeOfRawData;
            if (rva >= start && rva < start + size) {
                char name[IMAGE_SIZEOF_SHORT_NAME + 1] = {};
                memcpy(name, section->Name, IMAGE_SIZEOF_SHORT_NAME);
                return std::string(name);
            }
        }
        return "";
    }
}

namespace debug_harness::mem {

    region_info query(uint64_t address) {
        region_info info;
        if (address == 0) return info;

        MEMORY_BASIC_INFORMATION basic = {};
        if (VirtualQuery(reinterpret_cast<LPCVOID>(address), &basic, sizeof(basic)) != sizeof(basic)) return info;

        info.allocation_base = reinterpret_cast<uint64_t>(basic.AllocationBase);
        info.region_base = reinterpret_cast<uint64_t>(basic.BaseAddress);
        info.region_size = basic.RegionSize;
        info.protect = basic.Protect;
        info.state = basic.State;
        info.type = basic.Type;

        if (basic.State != MEM_COMMIT) return info; // reserved or free: not valid for access

        info.guarded = (basic.Protect & PAGE_GUARD) != 0;
        info.readable = protect_allows_read(basic.Protect) && !info.guarded;
        info.writable = protect_allows_write(basic.Protect) && !info.guarded;
        info.executable = protect_allows_execute(basic.Protect);
        info.valid = true;

        HMODULE module = nullptr;
        if (GetModuleHandleExA(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
                               reinterpret_cast<LPCSTR>(address), &module) &&
            module) {
            info.module_base = reinterpret_cast<uint64_t>(module);

            char path[MAX_PATH] = {};
            if (GetModuleFileNameA(module, path, MAX_PATH)) info.module_name = base_name(path);

            info.section_name = section_name_for(info.module_base, address);
        }

        return info;
    }

    bool safe_read(uint64_t address, void* out, size_t size) {
        if (!out || size == 0 || size > max_read_bytes) return false;
        if (address == 0) return false;

        const uint64_t end = address + size;
        if (end < address) return false; // wraps

        // Validate every region the span touches, not just the first.
        uint64_t cursor = address;
        while (cursor < end) {
            const auto region = query(cursor);
            if (!region.valid || !region.readable) return false;

            const uint64_t region_end = region.region_base + region.region_size;
            if (region_end <= cursor) return false; // no forward progress; refuse rather than spin
            cursor = region_end;
        }

        return raw_copy(out, reinterpret_cast<const void*>(address), size);
    }

    bool safe_read_u64(uint64_t address, uint64_t& out) {
        return safe_read(address, &out, sizeof(out));
    }

    bool safe_read_c_string(uint64_t address, size_t max_chars, std::string& out) {
        out.clear();
        if (max_chars == 0) return false;
        if (max_chars > max_read_bytes) max_chars = max_read_bytes;

        // Byte at a time: the string may end just before an unmapped page, and a bulk
        // read of max_chars would refuse a perfectly valid short string.
        for (size_t i = 0; i < max_chars; ++i) {
            char ch = 0;
            if (!safe_read(address + i, &ch, 1)) return i > 0; // partial read is still useful; nothing read is failure
            if (ch == '\0') return true;
            out.push_back(ch);
        }
        return true;
    }

    bool safe_read_w_string(uint64_t address, size_t max_chars, std::string& out_utf8) {
        out_utf8.clear();
        if (max_chars == 0) return false;
        if (max_chars > max_read_bytes / sizeof(wchar_t)) max_chars = max_read_bytes / sizeof(wchar_t);

        std::wstring wide;
        for (size_t i = 0; i < max_chars; ++i) {
            wchar_t ch = 0;
            if (!safe_read(address + i * sizeof(wchar_t), &ch, sizeof(ch))) break;
            if (ch == L'\0') break;
            wide.push_back(ch);
        }

        if (wide.empty()) {
            wchar_t probe = 0;
            return safe_read(address, &probe, sizeof(probe)); // empty string vs unreadable
        }

        const int needed =
            WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), nullptr, 0, nullptr, nullptr);
        if (needed <= 0) return false;

        out_utf8.resize(static_cast<size_t>(needed));
        WideCharToMultiByte(CP_UTF8, 0, wide.c_str(), static_cast<int>(wide.size()), &out_utf8[0], needed, nullptr,
                            nullptr);
        return true;
    }

    void arm_writes(bool armed, unsigned int auto_disarm_seconds) {
        auto& state = writes();
        std::lock_guard<std::mutex> lock(state.mutex);
        state.armed = armed;
        state.arm_expiry_ms = armed ? GetTickCount64() + static_cast<uint64_t>(auto_disarm_seconds) * 1000ull : 0;
    }

    bool writes_armed() {
        auto& state = writes();
        std::lock_guard<std::mutex> lock(state.mutex);
        if (!state.armed) return false;
        if (GetTickCount64() >= state.arm_expiry_ms) {
            state.armed = false; // expire in place
            state.arm_expiry_ms = 0;
            return false;
        }
        return true;
    }

    unsigned int write_arm_seconds_left() {
        auto& state = writes();
        std::lock_guard<std::mutex> lock(state.mutex);
        if (!state.armed) return 0;
        const uint64_t now = GetTickCount64();
        if (now >= state.arm_expiry_ms) return 0;
        return static_cast<unsigned int>((state.arm_expiry_ms - now) / 1000ull);
    }

    bool safe_write(uint64_t address, const void* data, size_t size, bool force, const std::string& source,
                   size_t& out_undo_index, std::string& out_error) {
        out_error.clear();

        if (!writes_armed()) {
            out_error = "writes are not armed";
            return false;
        }
        if (!data || size == 0 || size > max_write_bytes) {
            out_error = "size must be between 1 and " + std::to_string(max_write_bytes);
            return false;
        }
        if (address == 0) {
            out_error = "address is null";
            return false;
        }
        const uint64_t end = address + size;
        if (end < address) {
            out_error = "span wraps";
            return false;
        }

        // Every region the span touches must be committed, and writable unless forcing.
        uint64_t cursor = address;
        while (cursor < end) {
            const auto region = query(cursor);
            if (!region.valid) {
                out_error = "address is not committed";
                return false;
            }
            if (!region.writable && !force) {
                out_error = "region is not writable (pass force=1 to override)";
                return false;
            }
            const uint64_t region_end = region.region_base + region.region_size;
            if (region_end <= cursor) {
                out_error = "region walk made no progress";
                return false;
            }
            cursor = region_end;
        }

        // Capture the originals first: without them the write is not undoable.
        std::vector<uint8_t> old_bytes(size);
        const bool readable = query(address).readable;
        if (readable && !safe_read(address, old_bytes.data(), size)) {
            out_error = "could not capture the original bytes";
            return false;
        }
        if (!readable) old_bytes.assign(size, 0); // e.g. a forced write to PAGE_NOACCESS

        DWORD previous_protect = 0;
        bool protection_changed = false;
        if (force) {
            if (!VirtualProtect(reinterpret_cast<LPVOID>(address), size, PAGE_EXECUTE_READWRITE, &previous_protect)) {
                out_error = "VirtualProtect failed with " + std::to_string(GetLastError());
                return false;
            }
            protection_changed = true;
        }

        const bool wrote = raw_write(reinterpret_cast<void*>(address), data, size);

        if (protection_changed) {
            DWORD ignored = 0;
            VirtualProtect(reinterpret_cast<LPVOID>(address), size, previous_protect, &ignored);
        }

        if (!wrote) {
            out_error = "the write faulted";
            return false;
        }

        write_record record;
        record.address = address;
        record.old_bytes = std::move(old_bytes);
        record.new_bytes.assign(static_cast<const uint8_t*>(data), static_cast<const uint8_t*>(data) + size);
        record.timestamp_ms = GetTickCount64();
        record.source = source;
        record.reverted = false;

        auto& state = writes();
        std::lock_guard<std::mutex> lock(state.mutex);
        if (state.undo_log.size() >= undo_capacity) state.undo_log.erase(state.undo_log.begin());
        state.undo_log.push_back(std::move(record));
        out_undo_index = state.undo_log.size() - 1;
        return true;
    }

    std::vector<write_record> undo_log() {
        auto& state = writes();
        std::lock_guard<std::mutex> lock(state.mutex);
        return state.undo_log;
    }

    bool revert(size_t undo_index, std::string& out_error) {
        out_error.clear();

        uint64_t address = 0;
        std::vector<uint8_t> bytes;
        {
            auto& state = writes();
            std::lock_guard<std::mutex> lock(state.mutex);
            if (undo_index >= state.undo_log.size()) {
                out_error = "no such undo entry";
                return false;
            }
            if (state.undo_log[undo_index].reverted) {
                out_error = "already reverted";
                return false;
            }
            address = state.undo_log[undo_index].address;
            bytes = state.undo_log[undo_index].old_bytes;
        }

        DWORD previous_protect = 0;
        const bool needs_force = !query(address).writable;
        if (needs_force && !VirtualProtect(reinterpret_cast<LPVOID>(address), bytes.size(), PAGE_EXECUTE_READWRITE,
                                          &previous_protect)) {
            out_error = "VirtualProtect failed with " + std::to_string(GetLastError());
            return false;
        }

        const bool wrote = raw_write(reinterpret_cast<void*>(address), bytes.data(), bytes.size());

        if (needs_force) {
            DWORD ignored = 0;
            VirtualProtect(reinterpret_cast<LPVOID>(address), bytes.size(), previous_protect, &ignored);
        }

        if (!wrote) {
            out_error = "the revert write faulted";
            return false;
        }

        auto& state = writes();
        std::lock_guard<std::mutex> lock(state.mutex);
        if (undo_index < state.undo_log.size()) state.undo_log[undo_index].reverted = true;
        return true;
    }

    classification classify(uint64_t qword) {
        classification result;

        if (qword == 0) {
            result.kind = kind::null;
            result.text = "null";
            return result;
        }

        // Ordered cheapest-and-most-certain first. A small value cannot be a pointer
        // on x64 user-mode, so it is decided before any memory is probed.
        if (qword < 0x10000ull) {
            result.kind = kind::small_int;
            result.text = "smallint " + hex_string(qword) + " (" + std::to_string(qword) + ")";
            return result;
        }

        const auto region = query(qword);
        if (region.valid && region.readable) {
            if (region.executable) {
                result.kind = kind::code;
                result.text = "code:" + (region.module_name.empty() ? std::string("<anon>") : region.module_name) + "+" +
                              hex_string(qword - (region.module_base ? region.module_base : region.region_base));
                return result;
            }

            // Vtable: a read-only run of pointers into executable memory.
            if (!region.writable) {
                uint64_t slots = 0;
                for (uint64_t i = 0; i < 256; ++i) {
                    uint64_t slot = 0;
                    if (!safe_read_u64(qword + i * sizeof(uint64_t), slot)) break;
                    const auto target = query(slot);
                    if (!target.valid || !target.executable) break;
                    ++slots;
                }
                if (slots >= 4) {
                    result.kind = kind::vtable;
                    result.vtable_slots = slots;
                    result.text = "vtable:" + (region.module_name.empty() ? std::string("<anon>") : region.module_name) +
                                  "+" + hex_string(qword - (region.module_base ? region.module_base : region.region_base)) +
                                  " (" + std::to_string(slots) + " slots)";
                    return result;
                }
            }

            // Pointer to printable text.
            std::string text;
            if (safe_read_c_string(qword, 64, text) && looks_printable(text)) {
                result.kind = kind::ascii;
                result.text = "ascii:\"" + text + "\"";
                return result;
            }

            // Stack of the calling thread. NtCurrentTeb() is no use here: user-mode
            // winnt.h declares _TEB as an opaque type, so its NtTib members are not
            // reachable. GetCurrentThreadStackLimits is the documented equivalent.
            //
            // Only the *calling* thread's stack is recognised, which for an HTTP
            // request means the server thread. A pointer into another thread's stack
            // falls through to heap_ptr; acceptable for a hint.
            ULONG_PTR stack_low = 0;
            ULONG_PTR stack_high = 0;
            GetCurrentThreadStackLimits(&stack_low, &stack_high);
            if (stack_high != 0 && qword >= stack_low && qword < stack_high) {
                result.kind = kind::stack_ptr;
                result.text = "ptr:stack";
                return result;
            }

            result.kind = kind::heap_ptr;
            result.text = "ptr:" + (region.module_name.empty() ? std::string("heap") : region.module_name) + " (" +
                          std::to_string(region.region_base + region.region_size - qword) + " bytes readable)";
            return result;
        }

        // Not a usable pointer. Two plausible floats is the most common remaining
        // meaning in host structs (positions, extents, health/max pairs).
        float low = 0.0f;
        float high = 0.0f;
        const auto low_bits = static_cast<uint32_t>(qword & 0xFFFFFFFFull);
        const auto high_bits = static_cast<uint32_t>(qword >> 32);
        memcpy(&low, &low_bits, sizeof(low));
        memcpy(&high, &high_bits, sizeof(high));

        if (plausible_float(low) && plausible_float(high)) {
            result.kind = kind::float_pair;
            result.text = "float(" + float_string(low) + ", " + float_string(high) + ")";
            return result;
        }

        result.kind = kind::garbage;
        result.text = "garbage " + hex_string(qword);
        return result;
    }
}
