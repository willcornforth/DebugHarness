# Agent guide: driving the debug server

This guide is for an AI agent, or any script, talking to a running debug_harness
listener. It covers how to reach the server, how to write address expressions, what
each endpoint returns, and the habits that keep your conclusions trustworthy.

The server lives inside the host process and reads that process's own memory. Every
read is guarded, so a wrong address comes back as `ok:false` or a failed step instead
of a crash. You can test guesses cheaply. The only way to do damage is a write, and
writes are locked out by default (see [Writes](#writes)).

---

## 1. Connecting

| Fact | Value |
|---|---|
| Address | `http://127.0.0.1:<port>`. It binds to loopback only and is never reachable remotely. |
| Default port | `27015` (`debug_harness::default_port`). The host may pick another port, or `0` for one the OS chooses; `/ping` reports the actual port. |
| Off by default | The host must call `debug_harness::start()`, usually from a "Start listening" button in the panel. |
| Protocol | HTTP/1.0, one request per connection, `Connection: close`. Every response body is JSON. |
| Request size cap | 64 KiB |

**Always start with `GET /ping`.**
- If it fails to connect, the listener isn't running. Ask the user to start it; you
  cannot start it over HTTP.
- If it succeeds, note `module`, `base`, `preferredBase` and `writesArmed` before doing
  anything else.

### Clients

Use whichever client your shell has:

```powershell
# PowerShell wrapper; it URL-encodes the argument for you
.\tools\mem.ps1 ping
.\tools\mem.ps1 chain '@base[+0x3C]'
.\tools\mem.ps1 get '/host/state'          # a host-registered route, path given raw
```

```bash
# curl: --data-urlencode with -G does the encoding (see the "+" trap below)
curl -s "http://127.0.0.1:27015/ping"
curl -sG "http://127.0.0.1:27015/chain" --data-urlencode "e=@base[+0x3C]"
```

`mem.ps1` options: `-Port`, `-As`, `-N`, `-Count`, `-Value`, `-Since`, `-Force`, and
`-Raw` (print raw JSON).

### The `+` trap (read this)

The query decoder turns a bare `+` into a space, so `?e=@base[+0x3C]` sent unencoded
reaches the parser as `@base[ 0x3C]` and fails. **Always URL-encode expressions.**
`+` must become `%2B`, `[` becomes `%5B`, `]` becomes `%5D`, and `@` becomes `%40`.
`mem.ps1` and `curl -G --data-urlencode` do this for you. Hand-built URLs are where
it goes wrong.

---

## 2. Address expressions

The parameter `e=` takes an expression, read left to right:

```
root      := "va:" hex | "rva:" hex | "ida:" hex | "@" name
suffix    := "+" addend               add, no dereference
           | "[" [ "+" addend ] "]"   add, then dereference a qword
addend    := hex | Ns::NAME | NAME    hex must be 0x-prefixed
```

**Coordinate systems.** The module is whichever one the host configured; by default
it is the main executable.

| Root | Meaning |
|---|---|
| `va:0x7FF6...` | A live virtual address, used as is. |
| `rva:0x22C78F8` | An offset from the live module base. |
| `ida:0x1422C78F8` | A disassembler address. It is rebased by `live_base - preferredBase`, so you can paste addresses straight from IDA or Ghidra. |
| `@base` | The module base. This root is built in and always present. |
| `@name` | A root supplied by the host. List them with `/roots`. |

**Named addends.** `[+Player::OFF_HEALTH]` resolves through the host's symbol table.
List the names with `/offsets?filter=`. Prefer names over literal hex wherever the
host provides them, because they keep working when the host's offsets are updated.

**Examples**

```
@base+0x3C                     address of e_lfanew (no read)
@base[+0x3C]                   read the qword at base+0x3C
@local.player[+0x130][+0x60][]+0x3C
    player -> read +0x130 -> read +0x60 -> read +0 -> add 0x3C (the address of a field)
```

There is **no subtraction**. To look before an address, compute the target yourself and
use `va:`.

---

## 3. Endpoints

All endpoints are GET unless noted. `GET /routes` is authoritative: it also lists
endpoints the host added and marks any that a built-in hides (`"shadowed":true`).

| Endpoint | Parameters | Use it to |
|---|---|---|
| `/ping` | none | Check health. Returns module, base, preferredBase, imageSize, port, uptimeMs, requestCount, writesArmed, writeArmSecondsLeft. |
| `/routes` | none | Discover endpoints, including ones the host registered. |
| `/roots` | none | List `@base` plus the host's roots, each with `valid`, `value` and `note`. |
| `/addr` | `e` | Translate one address to va, rva and ida, with its module, section and protection. |
| `/region` | `e` | Get the VirtualQuery view: allocation and region base and size, protect, state, type, readable, writable, executable, guarded. |
| `/read` | `e`, `n` (default 16, max 4096), `as` | Read typed memory. `as` is one of `hex`, `u8`..`u64`, `i8`..`i64`, `f32`, `f64`, `ptr` (adds `points_to`), `cstr`, `wstr` (for strings, `n` is the maximum number of characters). |
| `/chain` | `e` | Get a trace of every step, showing **which link broke**. A broken chain still returns HTTP 200, with `ok:false`, `error` and `errorAt`. |
| `/struct` | `e`, `n` (default 0x100, max 0x1000, rounded down to whole qwords) | Guess the type of each qword: null, code, vtable, heap, stack, small integer, float pair, ascii or garbage. |
| `/vtable` | `e` (the object), `count` (default 64, max 512) | List the object's vtable slots, each with `index`, `indexHex` (the byte displacement), va, rva, ida, module and section. |
| `/scan` | `p` (an IDA-style pattern, `?` for a wildcard byte), `max` (default 8, max 256) | Search the configured module. Returns `totalHits`, `unique`, `truncated` and `hits`. |
| `/offsets` | `filter` | List the host's named constants. Returns an empty list with a `note` if the host provides none. |
| `/log` | `since` (an entry index) | Read the host's log. Returns 404 "not provided by host" if the host has no log. |
| `/write` | **POST**, with `e`, `v`, `as` (`hex`, `u8`..`u64`, `i8`..`i64`, `f32`, `f64`) and `force=1` | Write memory. Writes are gated; see below. |

**HTTP status codes**

| Code | Meaning |
|---|---|
| 200 | The request was handled. **Always check `ok` as well**, because `/chain` and failed reads can return 200 with `ok:false`. |
| 400 | A parameter is bad or missing. |
| 403 | Writes are not armed. |
| 404 | The endpoint doesn't exist, or the host doesn't provide that data. |
| 500 | A handler threw an exception. |
| 504 | A host route that waits on the game thread timed out. The host's render loop has probably stalled. |

Errors always come back as `{"ok":false,"error":"..."}`.

---

## 4. Writes

- `/write` returns **403 unless writes are armed in-process**, from the panel or by
  host code calling `mem::arm_writes`. Arming is deliberately impossible over HTTP.
- An arm expires on its own after 300 s by default. `/ping` reports how much time is
  left in `writeArmSecondsLeft`.
- Each write is at most 256 bytes. The original bytes are saved in an undo log (the
  last 64 entries), and the response includes `oldBytes` and `undoIndex`.
- `force=1` temporarily makes a non-writable page writable, for example to patch
  code. Only use it when the user explicitly asks for a code patch.

**Agent rules for writes:**
1. Never ask the user to arm writes unless they asked you to change memory.
2. Before writing, `/read` the target with the same `as`, and quote the current value
   back to the user.
3. Make one write at a time and confirm each with a `/read` afterwards.
4. Report the `undoIndex`. Reverting is done in-process, through the panel's Writes
   section or `mem::revert`. There is no HTTP endpoint for it.

---

## 5. Recipes

**Is my pointer chain still valid?** (for example, after the host program was updated)
```
/chain?e=@local.player[+Player::OFF_INVENTORY][+0x10][]
```
Read `steps[]`. The first step with `ok:false` is the link that broke. The step before
it gives the last good address. Run `/struct` on that address to see what is there
now.

**What is this unknown object?**
1. Run `/struct?e=<obj>&n=0x200` to get a guessed layout.
2. If qword 0 is classified as a vtable, run `/vtable?e=<obj>&count=64`. Take the ida
   addresses to the disassembler.
3. To find a live field such as health or a state value, use the panel's Structure
   inspector, which tracks how often each qword changes. Over HTTP, poll `/read`
   before and after an action you ask the user to perform, and compare.

**Which vtable slot is this function?** Run `/vtable` and match the `ida` addresses
against the disassembler. `indexHex` is the byte offset to use in a call such as
`call [rax+0xC0]`.

**Does this signature still match?** Run `/scan?p=48 8B C4 ? ? ...`. Check two things:
- `unique:true` and exactly one hit means the signature is good.
- More than one hit means it is ambiguous. Lengthen it past the first byte that
  differs between the hits.

**Translate an address from IDA:** `/addr?e=ida:0x1422C78F8` gives the live va and
the section it falls in.

**Call something the host exposes:** check `/routes` for host paths (for example
`/host/state`). These run on the host's render thread and return 504 if the host
stalls.

---

## 6. Interpreting results honestly

- **`null` from a float read means NaN or infinity.** JSON can't represent those
  values, so the server writes `null`. The bytes were read successfully; the value
  just isn't finite. Use `as=hex` to see the raw bits.
- **The scanner skips unreadable pages.** A match can't span a guard or no-access
  page, so an expected hit that crosses one won't appear.
- **`undoIndex` can shift.** Once the 64-entry undo log is full, the oldest entry
  is dropped and every index moves down by one. Check the panel's Writes section
  before reverting by index.
- **`/struct` classifications are guesses.** Vtable detection fires on any run of
  code pointers, and a "float pair" may just be two integers. Confirm with `/read`
  using an explicit `as`.
- **Live code can differ from the file on disk.** If the host (or anything else) has
  hooked a function, its first bytes in memory are a jump (`E9 xx xx xx xx`), not the
  original prologue. A prologue signature then misses, or matches a different
  function that happens to share those bytes. Before concluding "the function moved":
  - ask whether that function is hooked;
  - scan for bytes past the patched region, which is about 5 to 14 bytes in;
  - check whether the signature is unique in the disassembler database.
- **Everything is a snapshot.** Objects move or get freed between requests. A
  `/chain` that worked a second ago can fail now. Re-resolve from a root rather than
  caching raw `va:` values across steps.
- **`/log` `since` is a best-effort cursor** if the host trims old entries.
- When you report a finding to the user, include the exact expression and the
  `ida`/`rva` coordinates. Those are what they will paste into code.

---

## 7. Quick checklist for a session

1. Run `/ping` and record base, preferredBase and writesArmed.
2. Run `/routes` and `/roots` to see what the host exposes.
3. Run `/offsets?filter=` to learn the symbol names before writing literal hex.
4. Investigate with `/chain`, `/struct`, `/vtable`, `/scan` and `/addr`, URL-encoding
   every expression.
5. Write nothing unless the user asked for it and armed writes themselves.
6. If something looks broken, run `tools/smoke.ps1`. It checks the harness itself
   without depending on any particular host.
