# debug_harness

An in-process, game-agnostic memory debug harness for x64 Windows, packaged as a C++23
static library. A DLL that already lives inside a host process (a mod, an overlay, a
trainer-style tool) links it, configures it once, and drives it from **its own** render
frame. What you get:

- An **address-expression language**: `@root[+Ns::OFF_A][+0x60][]+0x3C` with per-step
  traces, so you can see which link in a pointer chain broke.
- A **structure inspector**: re-reads a span every frame or at 4 Hz, classifies each qword
  (code / vtable / heap / stack / ascii / float pair / small int / null), counts changes,
  and builds the pastable expression as you follow pointers.
- A **loopback HTTP server** (127.0.0.1 only, off by default) that serves the same
  operations as JSON, so scripts and agents can probe a live process with `curl`.
- An optional **Dear ImGui panel** that draws all of it inside the host's existing ImGui
  frame.

The library **does not set up ImGui**. It creates no ImGui context, no platform or renderer
backend, no D3D device, no window and no hooks. Those belong to the consumer.

## Safety model

- Every read goes through `mem::safe_read*`: `VirtualQuery` validation, then the copy under
  SEH. A wrong offset is a structured failure, never a crash. No code path bypasses it.
- The server binds `127.0.0.1` only, and nothing listens until the consumer calls `start()`.
- Writes need `mem::arm_writes`, which is **never reachable over HTTP**: only in-process UI
  can arm. The arm expires on its own (default 5 minutes). Every write records its original
  bytes in an undo log and can be reverted, even after the arm has expired.
- Host state is only touched on the render thread: a route handler posts work with
  `run_on_game_thread`, and `on_frame()` drains it. A host that stops rendering produces
  HTTP 504 instead of a hung request.
- Classification is a heuristic, and is presented as one.

## Layout

```
include/debug_harness/
  harness.hpp      public entry: host_config, configure, on_frame, register_route, log
  expr.hpp         address-expression parser/evaluator (pure, env-injected)
  mem.hpp          guarded reads, armed/undoable writes, qword classification
  inspect.hpp      inspector model: snapshot, refresh, classify, hex lines, path building
  live.hpp         binds expr to the running process (module base, roots, describe)
  scan.hpp         IDA-style signature scanner over the configured module
  http.hpp         HTTP/1.0 request parsing + JSON writer
  server.hpp       start/stop/running/port/get_stats, run_on_game_thread
  routes.hpp       built-in endpoint dispatch, route listing
  ui.hpp           ImGui-FREE view models (evaluator, watches, inspector, server, writes, session)
src/               one .cpp per header, plus host.cpp (config storage, route registry)
imgui/             OPTIONAL ImGui renderer over ui.hpp -- not part of the library target
tests/             host tests (small built-in framework), one CTest entry
tools/mem.ps1      PowerShell client for the HTTP endpoints; tools/smoke.ps1 smoke test
examples/consumer/ minimal consumer DLL (not built by default)
docs/DESIGN.md     the design contract
```

## Build and test

Requires CMake 3.25+, Visual Studio 2022 (MSVC, x64), C++23 (`/std:c++latest`).

```powershell
cmake -S . -B build -G "Visual Studio 17 2022" -A x64
cmake --build build --config Debug
ctest --test-dir build -C Debug --output-on-failure
```

If CMake cannot find Visual Studio (a `vswhere` error), put
`C:\Program Files (x86)\Microsoft Visual Studio\Installer` on `PATH`.

Options:

| Option | Default | Effect |
|---|---|---|
| `DEBUGHARNESS_BUILD_TESTS` | ON when top-level | builds `debug_harness_tests` |
| `DEBUGHARNESS_IMGUI_DIR` | empty | directory containing **your** `imgui.h`; enables the `debug_harness_imgui` target |
| `DEBUGHARNESS_BUILD_EXAMPLES` | OFF | builds `examples/consumer` (needs `DEBUGHARNESS_IMGUI_DIR`) |

To compile the panel and the example against your ImGui:

```powershell
cmake -S . -B build-imgui -G "Visual Studio 17 2022" -A x64 `
      -DDEBUGHARNESS_IMGUI_DIR=C:/path/to/your/imgui -DDEBUGHARNESS_BUILD_EXAMPLES=ON
cmake --build build-imgui --config Debug
```

The panel is verified against Dear ImGui 1.91.9 and 1.92.0 WIP.

## Integrating into your DLL

### 1. Link the library

As a subproject:

```cmake
add_subdirectory(third_party/DebugHarness)
target_link_libraries(my_overlay PRIVATE debug_harness)
```

For the ImGui panel, either

- set `DEBUGHARNESS_IMGUI_DIR` to the directory holding your `imgui.h` before the
  `add_subdirectory`, and link `debug_harness_imgui` (it compiles only the panel and
  links `debug_harness`; it does **not** compile ImGui, so your target must still link
  your own ImGui build), or
- skip that target and add `imgui/debug_harness_panel.cpp` to your own project, with
  `DebugHarness/imgui` and your ImGui directory on the include path.

The panel must be built against the same ImGui headers (and `imconfig.h`) as the ImGui
your DLL links.

### 2. Configure once

`configure()` only stores callbacks, so it is safe in `DllMain`.

```cpp
debug_harness::host_config config;
config.module_name = nullptr; // ida:/rva:/@base refer to the main exe; or e.g. "game.dll"
config.resolve_root = [](const std::string& name, uint64_t& out, std::string& note) {
    if (name != "local.player") return false;
    out = reinterpret_cast<uint64_t>(get_local_player());
    return true;
};
config.enumerate_roots = [] { return std::vector<debug_harness::root_entry>{ /* ... */ }; };
config.resolve_symbol = [](const std::string& qualified, uint64_t& out) { /* "Player::OFF_HEALTH" */ };
config.enumerate_symbols = [] { /* everything resolve_symbol knows, for GET /offsets */ };
config.log = [](debug_harness::log_level level, const std::string& text) { /* your logger */ };
config.log_entries = [] { /* optional; enables GET /log */ };
debug_harness::configure(std::move(config));
```

`@base` (the configured module's base) is built in; host roots follow it.

### 3. Call `on_frame()` every frame

From your existing render callback, on the render thread, every frame -- including frames
where the panel is hidden. It drains `run_on_game_thread` jobs and is cheap when idle.

### 4. Draw the panel, or your own UI

Inside your ImGui frame (after `ImGui::NewFrame()`, before `ImGui::Render()`):

```cpp
debug_harness::on_frame();
if (show_harness) debug_harness::panel::draw_window(&show_harness);
// or, inside a window/tab you already began:
debug_harness::panel::draw_contents();
```

Add your own sections (they appear under collapsing headers after the built-in ones):

```cpp
debug_harness::panel::add_section("Script", [] { /* ImGui calls */ });
```

Not using ImGui? Drive the view models in `ui.hpp` from your own renderer:

```cpp
static debug_harness::ui::session session;
session.tick(GetTickCount64());           // inspector re-read when due
session.inspector.open("@local.player");
for (size_t row : session.inspector.visible_rows()) { /* draw session.inspector.snapshot().rows[row] */ }
```

`ui.hpp` has no ImGui types: `evaluator`, `watches`, `inspector` (history with
anchor+delta paging, span choices 0x40..0x1000, every-frame / 4 Hz / manual refresh,
changed-only filter, lazy classification, follow/back/page, hex-line cache),
`server_control`, `write_log` (arm, seconds left, undo log, revert) and `session`.

### 5. Start the server

```cpp
std::string error;
if (!debug_harness::start(debug_harness::default_port, error)) { /* port in use, ... */ }
```

Do this from the render thread or a button (the panel's Server section has one), not from
`DllMain`: it opens a socket and spawns a thread. Call `debug_harness::stop()` from your
shutdown path before unloading.

### 6. Host-specific endpoints

```cpp
debug_harness::register_route("/my/thing", [](const debug_harness::http::request& request, int& status) {
    std::string answer;
    if (!debug_harness::run_on_game_thread([&] { answer = read_host_state(); })) {
        status = 504;
        return debug_harness::routes::error_body("host did not run the job in time");
    }
    status = 200;
    return answer;
}, "what it does");
```

Handlers run on the server thread; anything touching host state goes through
`run_on_game_thread`. Built-in paths take precedence: a host route registered on a
built-in path is listed as shadowed by `/routes` and never invoked.

See `examples/consumer/consumer_dll.cpp` for all of the above in one file.

## HTTP endpoints

All `GET` unless noted; every body is JSON. Default port 27015.

| Path | Parameters | Returns |
|---|---|---|
| `/ping` | | module, base, port, uptime, write-arm state |
| `/routes` | | every built-in and host-registered route |
| `/roots` | | `@base` plus the host's roots |
| `/addr` | `e=` | va / rva / ida, module, section, protection |
| `/region` | `e=` | `VirtualQuery` view of the address |
| `/read` | `e=` [`n=`] [`as=hex\|u8..u64\|i8..i64\|f32\|f64\|ptr\|cstr\|wstr`] | the value(s) |
| `/chain` | `e=` | per-step trace; a broken chain still answers 200 with `ok:false` |
| `/struct` | `e=` [`n=`] | qword-by-qword classification |
| `/vtable` | `e=` [`count=`] | slots of the object's vtable |
| `/scan` | `p=` [`max=`] | IDA-style pattern hits over the configured module |
| `/offsets` | [`filter=`] | `host_config::enumerate_symbols` |
| `/log` | [`since=`] | `host_config::log_entries`; 404 when the host provides none |
| `/write` | `POST`, `e=&v=` [`as=`] [`force=1`] | only while armed in-process; 403 otherwise |

Plus whatever the host adds with `register_route`.

## tools/mem.ps1

```powershell
.\tools\mem.ps1 ping
.\tools\mem.ps1 routes
.\tools\mem.ps1 roots
.\tools\mem.ps1 chain  '@base[+0x3C]'
.\tools\mem.ps1 read   '@base+0x3C' -As u32
.\tools\mem.ps1 struct '@base' -N 0x100
.\tools\mem.ps1 vtable 'va:0x7FF6A0001000' -Count 32
.\tools\mem.ps1 scan   '4D 5A 90 00'
.\tools\mem.ps1 addr   'rva:0x1000'
.\tools\mem.ps1 offsets Player
.\tools\mem.ps1 log -Since 100
.\tools\mem.ps1 write  '@base+0x10' -As u8 -Value 0x90   # requires arming in-process
.\tools\mem.ps1 get    '/my-host-route?x=1'              # any host-registered GET route
```

`-Port` selects a non-default port, `-Raw` prints the JSON unformatted.

## Coding style

snake_case throughout, in the style of the standard library: types, functions, variables
and enum values are all `snake_case`; private members carry a trailing underscore;
constants have no `k` prefix; macros are `UPPER_SNAKE`. Win32 names stay as they are. See
"Coding style" in `docs/DESIGN.md`.
