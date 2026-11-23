#pragma once

#include <cstdio>
#include <functional>
#include <string>
#include <vector>

namespace host_test {

    struct test_case {
        const char* name;
        std::function<void()> fn;
    };

    // Function-local static so registration order across translation units is safe.
    std::vector<test_case>& registry();

    struct failure_exception {
        std::string what;
    };

    // Throws failure_exception; run_all catches it per-case.
    void fail(const char* file, int line, const std::string& message);

    struct registrar {
        registrar(const char* name, std::function<void()> fn);
    };

    // Returns 0 when every case passed, 1 otherwise. Prints a per-case line.
    int run_all();

    std::string to_hex(unsigned long long value);
}

#define TEST(name)                                                                                                     \
    static void name();                                                                                                \
    static ::host_test::registrar registrar_##name(#name, name);                                                        \
    static void name()

#define CHECK(cond)                                                                                                    \
    do {                                                                                                               \
        if (!(cond)) ::host_test::fail(__FILE__, __LINE__, "CHECK failed: " #cond);                                     \
    } while (0)

#define CHECK_EQ(actual, expected)                                                                                     \
    do {                                                                                                               \
        const auto check_actual = (actual);                                                                             \
        const auto check_expected = (expected);                                                                         \
        if (!(check_actual == check_expected))                                                                           \
            ::host_test::fail(__FILE__, __LINE__,                                                                       \
                             std::string("CHECK_EQ failed: " #actual " == " #expected) +                               \
                                 " (actual = " + ::host_test::to_hex(static_cast<unsigned long long>(check_actual)) +     \
                                 ", expected = " + ::host_test::to_hex(static_cast<unsigned long long>(check_expected)) + \
                                 ")");                                                                                 \
    } while (0)

#define CHECK_STR_EQ(actual, expected)                                                                                 \
    do {                                                                                                               \
        const std::string check_actual = (actual);                                                                      \
        const std::string check_expected = (expected);                                                                  \
        if (check_actual != check_expected)                                                                              \
            ::host_test::fail(__FILE__, __LINE__,                                                                       \
                             std::string("CHECK_STR_EQ failed: got \"") + check_actual + "\", want \"" +                \
                                 check_expected + "\"");                                                                \
    } while (0)
