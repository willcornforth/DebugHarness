#include "harness.hpp"

#include <sstream>

namespace host_test {

    std::vector<test_case>& registry() {
        static std::vector<test_case> registry;
        return registry;
    }

    void fail(const char* file, int line, const std::string& message) {
        std::ostringstream out;
        out << file << ":" << line << ": " << message;
        throw failure_exception{out.str()};
    }

    registrar::registrar(const char* name, std::function<void()> fn) {
        registry().push_back(test_case{name, std::move(fn)});
    }

    std::string to_hex(unsigned long long value) {
        std::ostringstream out;
        out << "0x" << std::hex << value;
        return out.str();
    }

    int run_all() {
        size_t passed = 0;
        std::vector<std::string> failures;

        for (const auto& current : registry()) {
            try {
                current.fn();
                ++passed;
                std::printf("  PASS  %s\n", current.name);
            } catch (const failure_exception& failure) {
                failures.push_back(std::string(current.name) + "\n        " + failure.what);
                std::printf("  FAIL  %s\n        %s\n", current.name, failure.what.c_str());
            } catch (...) {
                failures.push_back(std::string(current.name) + "\n        unexpected exception");
                std::printf("  FAIL  %s\n        unexpected exception\n", current.name);
            }
        }

        std::printf("\n%zu passed, %zu failed, %zu total\n", passed, failures.size(), registry().size());
        return failures.empty() ? 0 : 1;
    }
}
