add_executable(debug_harness_tests
    main.cpp
    harness.cpp
    test_debugexpr.cpp
    test_debughttp.cpp
    test_debuginspect.cpp
    test_debuglive.cpp
    test_debugmem.cpp
    test_sigscanner.cpp
    test_host.cpp
    test_routes.cpp
    test_server.cpp
    test_ui.cpp
)
# The host tests reach the internal seams (route registry) directly.
target_include_directories(debug_harness_tests PRIVATE ${CMAKE_CURRENT_SOURCE_DIR} ${PROJECT_SOURCE_DIR}/src)
target_link_libraries(debug_harness_tests PRIVATE debug_harness)
if(MSVC)
    target_compile_options(debug_harness_tests PRIVATE /W4 /permissive- /EHsc)
    target_compile_definitions(debug_harness_tests PRIVATE _CRT_SECURE_NO_WARNINGS WIN32_LEAN_AND_MEAN NOMINMAX)
endif()

add_test(NAME debug_harness_tests COMMAND debug_harness_tests)
