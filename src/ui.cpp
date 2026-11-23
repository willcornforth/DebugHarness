#include "debug_harness/ui.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstring>
#include <format>
#include <iterator>

#include "debug_harness/harness.hpp"
#include "debug_harness/live.hpp"
#include "debug_harness/server.hpp"

namespace debug_harness::ui {

    float change_intensity(uint64_t changed_at_ms, uint64_t now_ms) {
        if (changed_at_ms == 0 || now_ms < changed_at_ms) return changed_at_ms == 0 ? 0.f : 1.f;
        const uint64_t age = now_ms - changed_at_ms;
        if (age >= change_fade_ms) return 0.f;
        return 1.f - static_cast<float>(age) / static_cast<float>(change_fade_ms);
    }

    uint64_t newest_change_in_line(const inspect::snapshot& snapshot, uint64_t offset) {
        uint64_t newest = 0;
        for (uint64_t index = offset / 8; index < offset / 8 + 2; ++index) {
            if (index < snapshot.rows.size()) newest = (std::max)(newest, snapshot.rows[index].changed_at_ms);
        }
        return newest;
    }

    std::string hex_bytes(const std::vector<uint8_t>& bytes) {
        std::string out;
        out.reserve(bytes.size() * 2);
        for (const auto byte : bytes) std::format_to(std::back_inserter(out), "{:02X}", byte);
        return out;
    }

    float as_float(uint32_t bits) {
        float value = 0.f;
        std::memcpy(&value, &bits, sizeof(value));
        return value;
    }

    bool is_followable(const inspect::row& row) {
        return row.readable && row.classified && row.kind != mem::kind::null && row.kind != mem::kind::small_int;
    }

    const char* kind_name(mem::kind kind) {
        switch (kind) {
        case mem::kind::null:
            return "null";
        case mem::kind::code:
            return "code";
        case mem::kind::vtable:
            return "vtable";
        case mem::kind::heap_ptr:
            return "heap_ptr";
        case mem::kind::stack_ptr:
            return "stack_ptr";
        case mem::kind::small_int:
            return "small_int";
        case mem::kind::float_pair:
            return "float_pair";
        case mem::kind::ascii:
            return "ascii";
        default:
            return "garbage";
        }
    }

    std::string region_origin(const mem::region_info& region) {
        if (!region.module_name.empty()) return region.module_name;
        if (region.type == MEM_MAPPED) return "mapped";
        if (region.type == MEM_IMAGE) return "image";
        return "private";
    }

    // --- evaluator ------------------------------------------------------------

    void evaluator::evaluate() {
        evaluate(live::env());
    }

    void evaluator::evaluate(const expr::env& env) {
        result_ = expr::evaluate(input.str(), env);
        has_result_ = true;
    }

    // --- watches --------------------------------------------------------------

    void watches::add(std::string expression) {
        expressions_.push_back(std::move(expression));
    }

    bool watches::remove(size_t index) {
        if (index >= expressions_.size()) return false;
        expressions_.erase(expressions_.begin() + static_cast<std::ptrdiff_t>(index));
        return true;
    }

    expr::result watches::evaluate(size_t index) const {
        return evaluate(index, live::env());
    }

    expr::result watches::evaluate(size_t index, const expr::env& env) const {
        if (index >= expressions_.size()) {
            expr::result missing;
            missing.error = "no such watch";
            return missing;
        }
        return expr::evaluate(expressions_[index], env);
    }

    // --- inspector ------------------------------------------------------------

    void inspector::reset_view() {
        snapshot_ = inspect::snapshot{};
        hex_lines_.clear();
        hex_lines_sample_ = 0;
        hex_lines_base_ = 0;
        hex_lines_size_ = 0;
        force_refresh_ = true;
    }

    void inspector::navigate(const std::string& expression, uint64_t address) {
        history_.push_back(nav_entry{expression, address, 0});
        if (history_.size() > history_capacity) history_.erase(history_.begin());
        reset_view();
        error_.clear();
    }

    bool inspector::go(const std::string& expression) {
        return go(expression, live::env());
    }

    bool inspector::go(const std::string& expression, const expr::env& env) {
        const auto result = expr::evaluate(expression, env);
        if (!result.ok) {
            error_ = result.error;
            return false;
        }
        navigate(expression, result.address);
        return true;
    }

    bool inspector::go() {
        return go(input.str());
    }

    bool inspector::open(const std::string& expression) {
        input.set(expression);
        return go(expression);
    }

    void inspector::back() {
        if (!can_go_back()) return;
        history_.pop_back();
        reset_view();
        error_.clear();
    }

    bool inspector::page(int64_t bytes) {
        if (history_.empty()) return false;
        auto& current = history_.back();
        const int64_t wanted = current.delta + bytes;
        // Only a delta that would take the view below address 0 is refused.
        if (wanted < 0 && current.anchor < static_cast<uint64_t>(-wanted)) return false;
        current.delta = wanted;
        reset_view();
        return true;
    }

    void inspector::to_anchor() {
        if (history_.empty() || history_.back().delta == 0) return;
        history_.back().delta = 0;
        reset_view();
    }

    std::string inspector::path() const {
        if (history_.empty()) return "";
        const auto& current = history_.back();
        std::string text = current.path();
        if (text.empty()) text = std::format("va:0x{:X}", current.address());
        return text;
    }

    bool inspector::follow(size_t row_index) {
        if (history_.empty() || row_index >= snapshot_.rows.size()) return false;
        inspect::classify(snapshot_, row_index);
        const auto& row = snapshot_.rows[row_index];
        if (!is_followable(row)) return false;

        // path(), not the raw expression: following out of a paged view has to carry the
        // page offset, and following out of a literal view still wants the va: form the
        // user can paste back. Copy both before navigate() replaces the snapshot.
        const std::string expression = inspect::append_follow(path(), row.offset);
        const uint64_t address = row.value;
        navigate(expression, address);
        return true;
    }

    void inspector::set_span_index(int index) {
        const int last = static_cast<int>(span_choices.size()) - 1;
        index = (std::clamp)(index, 0, last);
        if (index == span_index_) return;
        span_index_ = index;
        force_refresh_ = true;
    }

    void inspector::request_refresh(bool reclassify) {
        force_refresh_ = true;
        if (reclassify) force_reclassify_ = true;
    }

    bool inspector::tick(uint64_t now_ms) {
        now_ms_ = now_ms;
        if (history_.empty()) return false;

        const bool due = force_refresh_ || mode_ == refresh_mode::every_frame ||
                         (mode_ == refresh_mode::four_hz && now_ms - last_refresh_ms_ >= four_hz_interval_ms);
        if (due) {
            inspect::refresh(history_.back().address(), span(), snapshot_, now_ms, force_reclassify_);
            last_refresh_ms_ = now_ms;
            force_refresh_ = false;
            force_reclassify_ = false;
        }

        // Built from the snapshot, so it only needs rebuilding when the snapshot is
        // replaced -- not once per frame, which at the largest span would be 256 lines
        // of two strings each, every frame.
        if (hex_view_ && (hex_lines_sample_ != snapshot_.sample_count || hex_lines_base_ != snapshot_.base ||
                          hex_lines_size_ != snapshot_.size)) {
            hex_lines_ = inspect::hex_lines(snapshot_);
            hex_lines_sample_ = snapshot_.sample_count;
            hex_lines_base_ = snapshot_.base;
            hex_lines_size_ = snapshot_.size;
        }
        return due;
    }

    void inspector::set_hex_view(bool on) {
        hex_view_ = on;
        if (!on) {
            hex_lines_.clear();
            hex_lines_sample_ = 0;
            hex_lines_base_ = 0;
            hex_lines_size_ = 0;
        }
    }

    void inspector::reset_change_marks() {
        inspect::reset_changes(snapshot_);
    }

    const std::vector<size_t>& inspector::visible_rows() {
        visible_rows_.clear();
        for (size_t i = 0; i < snapshot_.rows.size(); ++i) {
            if (!changed_only_ || snapshot_.rows[i].change_count != 0) visible_rows_.push_back(i);
        }
        return visible_rows_;
    }

    void inspector::classify_row(size_t row_index) {
        if (row_index < snapshot_.rows.size()) inspect::classify(snapshot_, row_index);
    }

    void inspector::classify_visible(size_t first, size_t last) {
        last = (std::min)(last, visible_rows_.size());
        for (size_t line = first; line < last; ++line) classify_row(visible_rows_[line]);
    }

    // --- server_control -------------------------------------------------------

    server_control::server_control() : port_(static_cast<int>(debug_harness::default_port)) {}

    void server_control::set_port(int port) {
        port_ = (std::clamp)(port, 1024, 65535);
    }

    bool server_control::start() {
        last_error_.clear();
        if (debug_harness::start(static_cast<unsigned short>(port_), last_error_)) return true;
        if (last_error_.empty()) last_error_ = "start failed";
        debug_harness::log(log_level::error, "Debug harness failed to start: " + last_error_);
        return false;
    }

    void server_control::stop() {
        debug_harness::stop();
    }

    bool server_control::running() const {
        return debug_harness::running();
    }

    unsigned short server_control::listening_port() const {
        return debug_harness::running() ? debug_harness::port() : static_cast<unsigned short>(0);
    }

    // --- write_log ------------------------------------------------------------

    bool write_log::armed() const {
        return mem::writes_armed();
    }

    void write_log::set_armed(bool armed, unsigned int auto_disarm_seconds) {
        mem::arm_writes(armed, auto_disarm_seconds);
    }

    unsigned int write_log::seconds_left() const {
        return mem::write_arm_seconds_left();
    }

    std::vector<mem::write_record> write_log::entries() const {
        return mem::undo_log();
    }

    bool write_log::revert(size_t undo_index) {
        last_error_.clear();
        if (mem::revert(undo_index, last_error_)) return true;
        if (last_error_.empty()) last_error_ = "revert failed";
        debug_harness::log(log_level::error, "Revert failed: " + last_error_);
        return false;
    }

    // --- session --------------------------------------------------------------

    void session::add_section(std::string name, std::function<void()> draw, bool default_open) {
        for (auto& existing : sections_) {
            if (existing.name == name) {
                existing.draw = std::move(draw);
                existing.default_open = default_open;
                return;
            }
        }
        sections_.push_back(section{std::move(name), std::move(draw), default_open});
    }

    bool session::remove_section(const std::string& name) {
        const auto before = sections_.size();
        std::erase_if(sections_, [&name](const section& entry) { return entry.name == name; });
        return sections_.size() != before;
    }
}
