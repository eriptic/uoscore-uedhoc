# CMake tutorial for uoscore-uedhoc

This tutorial covers only the CMake features this project needs to replace the
current Makefile + `ExternalProject_Add` setup (see section 1 of
[REFACTROING.MD](REFACTROING.MD)). It is organised around the questions you
will actually face: how to describe the library once, how to configure it, how
consumers use it, and how it plugs into Zephyr.

> **Verification status.** The standalone examples in sections 2-9 were built
> with CMake 3.28, Ninja and GCC against this repository's sources (a
> `uoscore-uedhoc` static library from an explicit source list, `-Werror`
> presets, and a consumer project via `add_subdirectory`). The Zephyr examples
> in section 11 were first written without a Zephyr SDK; the implemented
> module was later built and tested with Zephyr 4.5.0-rc2.

> **Implementation.** Section 1 of REFACTROING.MD is now implemented. The
> files are authoritative where they differ from the teaching examples here:
> [CMakeLists.txt](CMakeLists.txt), [CMakePresets.json](CMakePresets.json),
> [cmake/](cmake/), [zephyr/](zephyr/), [test/CMakeLists.txt](test/CMakeLists.txt)
> and [samples/linux_sample.cmake](samples/linux_sample.cmake). The main
> difference: there is no `UOSCORE_UEDHOC_CRYPTO_ENGINE` choice. Mbed TLS is
> always needed (PSA and X.509 are used in every configuration), so TinyCrypt
> is the add-on option `UOSCORE_UEDHOC_TINYCRYPT`. The `CRYPTO_ENGINE` examples
> below remain as illustrations of a validated `STRING` option.

Contents

1. [Mental model](#1-mental-model)
2. [A minimal library project](#2-a-minimal-library-project)
3. [Targets, dependencies and scope keywords](#3-targets-dependencies-and-scope-keywords)
4. [Explicit source lists](#4-explicit-source-lists)
5. [Configuration inputs](#5-configuration-inputs)
6. [Presets](#6-presets)
7. [Dependencies](#7-dependencies)
8. [Toolchains, cross-compiling, sanitizers](#8-toolchains-cross-compiling-sanitizers)
9. [Consuming the library](#9-consuming-the-library)
10. [Tests](#10-tests)
11. [Zephyr](#11-zephyr)
12. [Makefile-to-CMake mapping](#12-makefile-to-cmake-mapping)
13. [Pitfalls and checklist](#13-pitfalls-and-checklist)
14. [Command cheat sheet](#14-command-cheat-sheet)
15. [Further reading](#15-further-reading)
16. [CMake 3.21-3.28 features used in this project](#16-cmake-321-328-features-used-in-this-project)

---

## 1. Mental model

CMake is a **build-system generator**, not a build tool. It runs in two steps:

| Step | Command | What happens |
|---|---|---|
| Configure + generate | `cmake -S . -B build -G Ninja` | Reads `CMakeLists.txt`, evaluates your options, checks the compiler, writes build files (Ninja/Makefiles) into `build/`. |
| Build | `cmake --build build` | Calls the generated build tool. Compiles, archives, links. |
| (Install) | `cmake --install build --prefix <dir>` | Copies headers/libraries to a prefix. Optional. |

Vocabulary you will use constantly:

- **Source dir / binary dir**: the checkout vs. the build directory (`-S`/`-B`).
  All outputs go to the binary dir. This directly satisfies "keep generated
  files and build outputs in dedicated binary directories"; you can have
  `build/host`, `build/asan`, `build/cortex-m` side by side from one checkout.
- **Target**: something to build (a library, an executable). A target carries
  *properties*: its sources, include directories, compile definitions,
  options, and the libraries it links. **Modern CMake is target-centric**:
  you attach everything to the target that needs it instead of setting global
  flags.
- **Cache variable**: a persistent, user-settable value stored in
  `CMakeCache.txt` (set with `-DNAME=value`). This is how configuration
  options are exposed.
- **Generator**: Ninja or Unix Makefiles. Zephyr uses Ninja by default.

Minimum version: the project requires **CMake 3.28**, the same minimum as
Zephyr (`cmake/modules/zephyr_default.cmake` declares
`cmake_minimum_required(VERSION 3.28.0)`). One minimum for every build means
the standalone build and the Zephyr build use the same CMake features and the
same policy behaviour. Section 16 lists what the project uses from versions
3.21-3.28.

`cmake_minimum_required()` does two things. It rejects older CMake versions,
and it sets every **policy** introduced up to that version to its NEW
behaviour. Policies are CMake's backward-compatibility switches (`CMP0128`,
...). Raising the minimum can therefore change a build even without other edits.
Read the new policies with `cmake --help-policy CMP0128`.

## 2. A minimal library project

A top-level `CMakeLists.txt` that builds the library from the source tree:

```cmake
cmake_minimum_required(VERSION 3.28)
project(uoscore_uedhoc LANGUAGES C)

add_library(uoscore-uedhoc STATIC
  src/common/byte_array.c
  src/edhoc/initiator.c
  # ... every file explicitly (see section 4)
)

target_include_directories(uoscore-uedhoc PUBLIC inc)
target_compile_features(uoscore-uedhoc PUBLIC c_std_17)   # consumers need >= C17
set_target_properties(uoscore-uedhoc PROPERTIES
  C_STANDARD 17 C_STANDARD_REQUIRED ON C_EXTENSIONS OFF)  # -std=c17
```

The project uses the same C standard as Zephyr: C17 without GNU extensions.
In Zephyr, C17 is both the default and the minimum (`CONFIG_STD_C17`; the
other choice is C23), and `CONFIG_GNU_C_EXTENSIONS` is off by default, so
Zephyr compiles with `-std=c17`.

`c_std_17` is a *minimum* for the target and its consumers. It does not pick a
flag: GCC 13 defaults to GNU C17, which already satisfies C17, so CMake would
add no `-std` flag at all. `C_STANDARD 17` with `C_EXTENSIONS OFF` asks for
exactly ISO C17 (`-std=c17`). Under policy CMP0128 (NEW since 3.22),
`C_EXTENSIONS OFF` is honoured. With the old policy (minimum 3.20) the library
was silently compiled as GNU C17 with extensions.

The real file uses a header set instead of `target_include_directories()`; see
section 16.

Build it:

```sh
cmake -S . -B build/host -G Ninja
cmake --build build/host          # produces build/host/libuoscore-uedhoc.a
```

Notes:

- `project(... LANGUAGES C)` avoids probing for a C++ compiler.
- The archive name `libuoscore-uedhoc.a` is the same as the Makefile's
  `LIB_NAME`, derived from the target name.
- Dependency tracking (`-MMD -MP -MF` in the Makefile) is automatic.
- Compiler choice comes from the environment or a toolchain file, **not** from
  `CC=` inside `CMakeLists.txt` (section 8).

### 2.1 `project()` is not the target

`project()` and the target are different things:

| Command | What it defines |
|---|---|
| `project(uoscore_uedhoc LANGUAGES C)` | The **project**: a name and the enabled languages. It makes CMake detect the C compiler and sets variables such as `PROJECT_NAME`, `PROJECT_SOURCE_DIR` and `PROJECT_BINARY_DIR`. It builds nothing. |
| `add_library(uoscore-uedhoc STATIC ...)` | The **target**: the thing that is built (here `libuoscore-uedhoc.a`), with its sources. This is the line that "defines the library". |
| `target_include_directories(uoscore-uedhoc ...)` and the other `target_*` commands | The target's **properties**: includes, definitions, options, linked libraries. |

One project can contain many targets (a library, tests, samples), and the
project name is not used to link anything. Consumers refer to the **target
name** (`uoscore-uedhoc`, or the alias `uoscore-uedhoc::uoscore-uedhoc`).

You can see this in the existing `test/CMakeLists.txt`: `project(auto_test)` only
names the project. The target `app` is created by `find_package(Zephyr)`, and
`add_library(test STATIC IMPORTED GLOBAL)` creates the imported target that
wraps the Make-built archive. In a Zephyr application, `find_package(Zephyr)`
must come **before** `project()`.

### 2.2 Do we need `VERSION` in `project()`?

No. `VERSION` is optional, and this project does not need it to build. Leaving
it out also avoids a second copy of the version number: the release process in
the README (`npm version <major|minor|patch>`) updates `package.json` and
creates the tag `vX.Y.Z` (currently `3.2.0`), so a hard-coded
`VERSION 1.0.0` in `CMakeLists.txt` would be both wrong and one more place to
bump.

When is a CMake-side version useful?

- `find_package(uoscore-uedhoc 3.2 REQUIRED)` version checks for an installed
  package (`write_basic_package_version_file`, section 9.2).
- Embedding the version in a header or a package file.
- Reporting it from `add_subdirectory` consumers via `PROJECT_VERSION`.

If you need it, keep `package.json` as the single source of truth and read it
instead of retyping it (checked with CMake 3.28; `string(JSON)` needs 3.19 or
newer):

```cmake
file(READ "${CMAKE_CURRENT_SOURCE_DIR}/package.json" _pkg)
string(JSON _version GET "${_pkg}" version)      # "3.2.0"
project(uoscore_uedhoc VERSION ${_version} LANGUAGES C)
```

Only add this when one of the uses above exists. Zephyr's integration does not
use it.

### 2.3 Finding out what a command does

CMake documents itself, so you do not need a browser:

```sh
cmake --help-command add_library        # full manual page for one command
cmake --help-command-list               # every command name
cmake --help-variable CMAKE_BUILD_TYPE  # a variable
cmake --help-property INTERFACE_INCLUDE_DIRECTORIES
cmake --help-policy CMP0077
cmake --help-module FetchContent        # a bundled module (include(...))
cmake --help-manual cmake-buildsystem   # concept manual (7)
```

Same content online: <https://cmake.org/cmake/help/latest/>, with a search box
and a version selector (use the version you require). Rules of thumb:

- The first section of a command's page lists its signatures; most commands
  have several (`add_library(<name> STATIC ...)` vs `add_library(<name> ALIAS ...)`).
- A command name tells you its family: `target_*` act on one target,
  `set_*`/`get_*` read or write properties, `*_ifdef` are Zephyr-only
  conveniences, `zephyr_*` come from Zephyr's `extensions.cmake`.
- Debugging: `cmake --trace-expand`, `cmake -LH` (list cache variables with
  help), `message(STATUS "x=${x}")`, and `cmake --build build -v` (show the
  real compiler command lines).
- Zephyr functions are documented in Zephyr's CMake docs and defined in
  `cmake/modules/extensions.cmake` in the Zephyr tree; read the function body
  when the documentation is thin.

### 2.4 Command reference for this project

The commands you will meet, grouped by purpose. "Where" refers to the section
that uses it.

**Project and language**

| Command | What it does | Where |
|---|---|---|
| `cmake_minimum_required(VERSION x)` | Declares the minimum CMake version and sets policy behaviour. First line. | 2 |
| `project(name [VERSION v] [LANGUAGES C])` | Names the project, enables languages, sets `PROJECT_*` variables. | 2.1 |
| `include(file-or-module)` | Runs another `.cmake` file or bundled module in the current scope. | 4 |
| `add_subdirectory(dir [binary_dir] [EXCLUDE_FROM_ALL] [SYSTEM])` | Processes `dir/CMakeLists.txt` as part of this build. `SYSTEM` (3.25) makes its include directories system includes for consumers. | 9.1, 16 |
| `block([PROPAGATE vars])` / `endblock()` | A local variable scope inside a file (3.25). | 16 |
| `message(STATUS\|WARNING\|FATAL_ERROR "text")` | Prints a message; `FATAL_ERROR` stops configuration. | 5.3 |

**Targets**

| Command | What it does | Where |
|---|---|---|
| `add_library(name STATIC\|OBJECT\|INTERFACE\|IMPORTED [srcs])` | Creates a library target. | 2, 3 |
| `add_library(ns::name ALIAS name)` | Another name for the same target. | 9 |
| `add_executable(name srcs)` | Creates an executable target. | 9.1 |
| `target_sources(t PRIVATE\|PUBLIC files)` | Adds source files to an existing target. | Zephyr: `app` |
| `target_include_directories(t SCOPE dirs)` | Include paths (`-I`). | 3 |
| `target_compile_definitions(t SCOPE X=1)` | Preprocessor definitions (`-D`). | 5.4 |
| `target_compile_options(t SCOPE flags)` | Compiler flags. | 5.7 |
| `target_sources(t PUBLIC FILE_SET HEADERS BASE_DIRS d FILES h...)` | Header set (3.23): lists headers; the base directory becomes an include directory. | 16 |
| `target_compile_features(t SCOPE c_std_17)` | Required language standard. | 2 |
| `target_link_libraries(t SCOPE libs)` | Links libraries or other targets and inherits their usage requirements. | 7, 9 |
| `target_link_options(t SCOPE flags)` | Linker flags. | 8 |
| `set_target_properties(t PROPERTIES ...)` | Sets properties (output name, `C_EXTENSIONS`, ...). | 2 |
| `add_dependencies(a b)` | Ordering without linking (used by the Make bridge we remove). | |

`SCOPE` means `PRIVATE`, `PUBLIC` or `INTERFACE` (section 3).

**Variables, options and logic**

| Command | What it does | Where |
|---|---|---|
| `set(VAR value)` | Normal variable (visible in this directory and below). | 4 |
| `set(VAR value CACHE TYPE "doc")` | Cache variable that users can override with `-DVAR=...`. | 5.1, 5.2 |
| `option(NAME "doc" ON\|OFF)` | Boolean cache variable. | 5.1, 5.3 |
| `set_property(CACHE VAR PROPERTY STRINGS a b)` | Drop-down choices in GUIs; no validation. | 5.3 |
| `if() / elseif() / else() / endif()` | Conditions: `if(VAR)`, `if(A IN_LIST lst)`, `if(NOT x STREQUAL "")`. | 5.3 |
| `foreach(x IN ITEMS ...)` / `endforeach()` | Loop. | 5.4 |
| `list(APPEND\|TRANSFORM ...)` | Modify a list variable. | 4, 11 |
| `file(READ ...)`, `file(GLOB ... CONFIGURE_DEPENDS ...)` | File access; glob only for tests. | 2.2, 4 |
| `string(JSON out GET json key)` | Read JSON (CMake 3.19+). | 2.2 |
| `$<...>` generator expressions | Conditions evaluated at build time, e.g. `$<C_COMPILER_ID:GNU>`. | 5.7 |

**Dependencies, install, test**

| Command | What it does | Where |
|---|---|---|
| `find_package(Name [REQUIRED])` | Locates an installed package and imports its targets. | 7 |
| `FetchContent_Declare` / `FetchContent_MakeAvailable` | Downloads a dependency and adds it. | 9.3 |
| `install(TARGETS\|DIRECTORY\|EXPORT ...)` | Defines what `cmake --install` copies. | 9.2 |
| `enable_testing()` / `add_test(NAME n COMMAND c)` | CTest registration. Not used here: tests are a Zephyr app. | 10 |

**Zephyr-only (section 11)**

| Command | What it does |
|---|---|
| `find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})` | Loads Zephyr's build system; creates the `app` target. |
| `zephyr_library_named(name)` | Starts a module library target (inside a module). |
| `zephyr_library_sources(files)` / `zephyr_library_sources_ifdef(CONFIG_X files)` | Adds sources to the current Zephyr library. |
| `zephyr_library_compile_definitions(X)` / `..._ifdef(CONFIG_X X)` | Definitions for the current Zephyr library. |
| `zephyr_library_link_libraries(lib)` | Links against another target such as `mbedtls_iface`. |
| `zephyr_include_directories(dir)` | Include path for all Zephyr targets. |
| `ZEPHYR_CURRENT_MODULE_DIR`, `ZEPHYR_EXTRA_MODULES` | Variables: the module's checkout directory; extra module paths set before `find_package(Zephyr)`. |

**Legacy commands to avoid in new code** (they appear in the current test
`CMakeLists.txt`): `include_directories`, `add_definitions`, `link_libraries`,
`file(GLOB)` without `CONFIGURE_DEPENDS`, and `ExternalProject_Add` for building
our own library. Use the `target_*` forms and a real target instead.

## 3. Targets, dependencies and scope keywords

This section builds up in steps: first the big picture, then the keywords,
then the rules for this project. A small example was built and run to check
every claim.

### 3.1 Big picture

- A **target** is something CMake builds. Here: our library, a test app, a sample.
- A target has **settings**: source files, include directories, compiler
  definitions (`-D`), compiler options, and linked libraries.
- A target can **link** another target. The first target is then a
  **consumer** of the second one.

```cmake
add_library(uoscore-uedhoc STATIC ...)          # the library
add_executable(app main.c)                      # the consumer
target_link_libraries(app PRIVATE uoscore-uedhoc)   # app uses the library
```

Every setting answers one question: **who needs it?** CMake wants you to
state the answer. You do that with a scope keyword.

### 3.2 Two audiences for a setting

A library has two audiences.

1. **The library itself**, while its `.c` files are compiled.
2. **The consumers**, while their `.c`/`.cpp` files include the library's headers.

Some settings matter to one audience only. Some matter to both. Real examples
from this project:

| Setting | Library's `.c` files need it | Consumers need it | Why |
|---|---|---|---|
| `-Iinc` | yes | yes | Apps include `oscore.h` and `edhoc.h` from there. |
| `-Iexternals/mbedtls/include` | yes | no | Only `src/` includes `<psa/crypto.h>` and `<mbedtls/...>`. |
| `-DMBEDTLS` | yes | no | Only `src/` has `#ifdef MBEDTLS`. |
| `-DOSCORE_INTERACTIONS_COUNT=5` | yes | yes | Changes `sizeof(struct context)`, which the app allocates (3.7). |
| `-Wall -Werror` | yes | no | Our warning policy. Not the app's business. |

### 3.3 The scope keyword

`PRIVATE`, `PUBLIC` and `INTERFACE` tell CMake which audience gets the
setting. Each `target_*` command takes one of them.

| Keyword | Library's own `.c` files | Consumers | Meaning |
|---|---|---|---|
| `PRIVATE` | yes | no | "Only I need this." |
| `PUBLIC` | yes | yes | "I need this, and so does everyone who uses me." |
| `INTERFACE` | no | yes | "I do not need this, but my users do." |

The commands that take a scope keyword:

| Command | The setting it carries |
|---|---|
| `target_include_directories` | `-I` paths |
| `target_compile_definitions` | `-D` macros |
| `target_compile_options` | compiler flags |
| `target_link_options` | linker flags |
| `target_sources` | source files |
| `target_link_libraries` | other libraries |
| `target_compile_features` | language standard, e.g. `c_std_17` |

### 3.4 What "propagated to consumers" means

When `app` links `uoscore-uedhoc`, CMake does this automatically:

1. It takes every `PUBLIC` and `INTERFACE` setting of the library.
2. It adds them to `app`'s compile and link commands.

This is called **propagation**. The `PUBLIC`/`INTERFACE` settings of a target
are also called its **usage requirements**: what a user must do to use it
correctly. You do not copy any flags by hand. The consumer's `CMakeLists.txt`
stays short.

Propagation also continues down a chain. If `app` links `libA`, and `libA`
links `libB` with `PUBLIC`, then `app` receives `libB`'s `PUBLIC` settings too.
With `PRIVATE` the chain stops at `libA`.

Propagation needs the consumer to link a **CMake target**, not just a `.a`
file. Section 3.8 shows when that holds across separate projects.

### 3.5 Public and private headers

**Definition.** A *public header* is a header that code outside the library
compiles. Outside code means applications, samples and tests. A *private
header* is compiled only by the library's own `.c` files.

The C preprocessor copies an included header's text into the including file.
So when an app includes `oscore.h`, the compiler sees `oscore.h` **plus every
header it includes, recursively**. Your intuition is right: the fully unfolded
include tree of a top-level header is public. A macro that changes any file in
that tree changes what the app compiles.

In this project there are three levels. Each level contains the one before it.

| Level | Headers | Count |
|---|---|---|
| 1. API entry headers | `edhoc.h`, `oscore.h`. Apps and samples include these. | 2 |
| 2. Unfolded API tree (public in effect) | Level 1 plus everything they include. See the list below. | 17 |
| 3. Reachable headers | Everything under `inc/`, because `inc/` is a `PUBLIC` include directory. | 88 |

Level 2, computed by following every `#include` in `inc/`:

- From `edhoc.h`: `common/byte_array.h`, `common/memcpy_s.h`,
  `common/oscore_edhoc_error.h`, `common/print_util.h`,
  `edhoc/edhoc_method_type.h`, `edhoc/hkdf_info.h`, `edhoc/messages.h`,
  `edhoc/suites.h`.
- From `oscore.h`: the four `common/` headers above, plus `oscore/nvm.h`,
  `oscore/oscore_coap.h`, `oscore/oscore_coap_defines.h`,
  `oscore/oscore_interactions.h`, `oscore/replay_protection.h`,
  `oscore/security_context.h`, `oscore/supported_algorithm.h`.

**Not** in level 2: `edhoc_internal.h`, `edhoc/runtime_context.h`,
`edhoc/buffer_sizes.h`, `common/crypto_wrapper.h`, `common/unit_test.h` and all
48 files in `inc/cbor/`. These are internal headers. They only sit in `inc/`
because the library's `.c` files include them from there.

Why level 3 matters: CMake shares **directories**, not single files. Because
`inc/` is `PUBLIC`, a consumer *can* include any of the 88 headers. The tests
already do this: they include `common/unit_test.h`, `oscore/option.h`,
`edhoc/retrieve_cred.h` and `edhoc/plaintext.h`. The README does not say which
headers are API ("The folder `inc` contains all header file").

**A real private header:** `src/common/crypto_p256.h`. Only
`src/common/crypto_p256.c` and `src/common/crypto_wrapper.c` include it, with
`#include "crypto_p256.h"`. The compiler finds it next to the including file,
so no `-I` is needed. `src/` is on no include path at all, so a consumer
cannot include it by accident. That is the ideal private header.

**Recommendation for the refactoring.** Make level 3 equal to level 2. Move the
internal headers out of the public include directory, for example to
`src/include/` or `inc/internal/` as a `PRIVATE` include directory. Tests
that need internal headers then get that directory explicitly. After that,
"public" has one exact meaning: the unfolded tree of `edhoc.h` and `oscore.h`.

### 3.6 Which macros must be PUBLIC?

**Rule:** a macro must be `PUBLIC` if it changes any header that a consumer
compiles. If not, it must be `PRIVATE`.

A macro can change a header in three ways:

1. **Struct size or fields.** The app allocates the struct. The library
   accesses it. Both must agree on the layout.
2. **Macro or inline definition.** The app expands it with its own view.
3. **A declaration appears or disappears.**

The configuration macros in the level-2 headers (taken from the code):

| Macro | Header | Effect | Kind |
|---|---|---|---|
| `OSCORE_INTERACTIONS_COUNT` (default 3) | `oscore/oscore_interactions.h` | Size of `interactions[]` in `struct req_resp_context`, part of `struct context` | 1 |
| `OSCORE_SERVER_REPLAY_WINDOW_SIZE` (default 32) | `oscore/replay_protection.h` | Size of `window[]`, part of `struct context` | 1 |
| `OSCORE_MAX_URI_PATH_LEN` (default 30) | `oscore/oscore_coap_defines.h` | Size of `uri_paths[]` in each interaction, part of `struct context` | 1 |
| `OSCORE_MAX_PLAINTEXT_LEN`, `E_OPTIONS_BUFF_MAX_LEN`, `I_OPTIONS_BUFF_MAX_LEN` | `oscore.h` | Buffer-size constants that an app can use to size its buffers | 2 |
| `K_SSN_NVM_STORE_INTERVAL`, `F_NVM_MAX_WRITE_FAILURE` | `oscore.h` | NVM constants | 2 |
| `OSCORE_SSN_OVERFLOW_VALUE` | `oscore/security_context.h` | Constant | 2 |
| `VLA` | `common/byte_array.h` | Definition of the `BYTE_ARRAY_NEW` macro | 2 |
| `DEBUG_PRINT` | `common/print_util.h` | Debug strings and print macros | 2 |
| `OSCORE_NVM_SUPPORT` | `oscore/nvm.h` | Declarations of `nvm_write_ssn`/`nvm_read_ssn` | 3 |

The Linux samples show why kind 1 is serious. They allocate the context
themselves (`struct context c_client;` in
`samples/linux_oscore/client/src/main.cpp`), then pass it to library functions
that read and write all its fields.

Macros used **only in internal headers or in `src/`** do not need `PUBLIC`
for API consumers:

| Macro | Used in | Reached from `edhoc.h`/`oscore.h`? |
|---|---|---|
| `C_I_SIZE`, `C_R_SIZE`, `CRED_I_SIZE`, `EAD_SIZE`, ... | `edhoc/buffer_sizes.h` -> `edhoc/runtime_context.h` | No. `struct runtime_context` is internal. |
| `UNIT_TEST` | `common/unit_test.h` | No. Tests include it directly. |
| `MESSAGE_4`, `MBEDTLS`, `TINYCRYPT`, `COMPACT25519` | `src/` only | No |

Two of these need care while level 3 is larger than level 2 (section 3.5):

- A test that includes `common/unit_test.h` must see `UNIT_TEST`.
- A consumer that includes `edhoc_internal.h` must see the `*_SIZE` values.

`PUBLIC` is harmless for these, and safe as long as internal headers are
reachable. After the headers are split, make them `PRIVATE` (or test-only).

Include directories follow the same rule. No level-2 header includes a
zcbor, Mbed TLS, PSA or compact25519 header. Only `inc/cbor/*_types.h` include
`<zcbor_common.h>`, and those are internal. So the zcbor include directory can
be `PRIVATE` for API consumers. The zcbor *library* must still be on the final
link line (section 3.10).

### 3.7 Example with the real library (built and run)

Setup: a standalone C++ project, like a Linux sample migrated to CMake. It
includes `oscore.h`, allocates `struct context`, and links the library. The
library is configured with `OSCORE_INTERACTIONS_COUNT=5`.

```cmake
# app/CMakeLists.txt
cmake_minimum_required(VERSION 3.20)
project(linux_oscore_client LANGUAGES C CXX)

set(UOSCORE_UEDHOC_OSCORE_INTERACTIONS_COUNT 5 CACHE STRING "")
add_subdirectory(path/to/uoscore-uedhoc uoscore-uedhoc)

add_executable(client main.cpp)
target_link_libraries(client PRIVATE uoscore-uedhoc::uoscore-uedhoc)
```

```cpp
// main.cpp (same include style as samples/linux_oscore/client/src/main.cpp)
extern "C" {
#include "oscore.h"
}
int main() { printf("%zu\n", sizeof(struct context)); }
```

Inside the library's `CMakeLists.txt`, the option becomes:

```cmake
target_compile_definitions(uoscore-uedhoc PUBLIC OSCORE_INTERACTIONS_COUNT=5)
target_compile_definitions(uoscore-uedhoc PRIVATE MBEDTLS COMPACT25519)
```

Compiler command lines (from `cmake --build -v`), definitions only:

```text
library .c files : -DCOMPACT25519 -DMBEDTLS -DOSCORE_INTERACTIONS_COUNT=5
main.cpp         :                          -DOSCORE_INTERACTIONS_COUNT=5
```

- `OSCORE_INTERACTIONS_COUNT=5` is `PUBLIC`. It reached `main.cpp`.
- `MBEDTLS` and `COMPACT25519` are `PRIVATE`. They did not reach `main.cpp`.

Result: `sizeof(struct context)` is **856** in the app and **856** in the
library. They match.

Without propagation, the app sees the header default `3` and computes **736**
bytes, while the library uses **856**. Section 3.8, case C, shows this exact
result. The app allocates 736 bytes. The library writes up to byte 856. This
is a silent memory corruption, and neither the compiler nor the linker warns.

(To measure the library's own view, the demo compiled one extra file into the
library target that returns `sizeof(struct context)`. This is only a test aid.)

### 3.8 Does propagation reach a standalone project?

Yes, if the standalone project receives the library as a **CMake target**. It
does not need to be the same project, repository or `CMakeLists.txt`. The
three cases below were built and run with the C++ app from 3.7.

| Case | How the app's `CMakeLists.txt` gets the library | Propagation | `sizeof(struct context)` app / library |
|---|---|---|---|
| A | `add_subdirectory(<lib>)` or `FetchContent_MakeAvailable` | Yes | 856 / 856 |
| B | Library installed with `install(EXPORT ...)`; app uses `find_package(uoscore-uedhoc)` | Yes | 856 / 856 |
| C | App links the `.a` file by path and adds `-I<lib>/inc` by hand | **No** | 736 / 856 (mismatch) |

**Case A** adds the library's `CMakeLists.txt` to the app's build. CMake sees
the real target with all its properties. `FetchContent` downloads the source and
then does the same thing.

**Case B** works through the exported targets file. `install(EXPORT ...)`
writes the target's usage requirements into
`lib/cmake/uoscore-uedhoc/uoscore-uedhocConfig.cmake`. The generated file
contained:

```cmake
INTERFACE_COMPILE_DEFINITIONS "OSCORE_INTERACTIONS_COUNT=5"
INTERFACE_COMPILE_FEATURES "c_std_17"
INTERFACE_INCLUDE_DIRECTORIES "${_IMPORT_PREFIX}/include/uoscore-uedhoc"
```

`find_package` reads this file and creates an imported target with the same
usage requirements. Only `PUBLIC` and `INTERFACE` settings are written. Two
consequences:

- The values are **frozen at install time**. The app cannot pick another
  `OSCORE_INTERACTIONS_COUNT`; it must use the installed configuration. Each
  configuration needs its own install prefix.
- Imported include directories are passed as `-isystem`, not `-I`. Warnings
  from those headers are then suppressed in the app. This is normal.

Exported include paths must not point into the source tree. Use
`$<BUILD_INTERFACE:...>` and `$<INSTALL_INTERFACE:...>` (section 9.2), or keep
those directories `PRIVATE`.

**Case C** is what plain Makefiles do, and what the current Zephyr test and
samples do with `ExternalProject_Add` plus an `IMPORTED` archive. A file path
carries no usage requirements. The app must repeat every `PUBLIC` setting by
hand. In practice it misses one, and the struct sizes differ.

So when the Linux samples move to CMake, each sample gets its own
`CMakeLists.txt` with its own `project()`. It uses case A (simplest) or case B
(when testing an installed library). It must never use case C.

**Zephyr is different.** Zephyr does not use `target_link_libraries(app ...)`
for module libraries. It links all `zephyr_library` archives into the final
image. A module library's own settings therefore do not reach `app`. The Zephyr
helper functions decide the scope (from Zephyr's `extensions.cmake`):

| Zephyr helper | Expands to | Reaches the app? |
|---|---|---|
| `zephyr_library_compile_definitions(X)` | `target_compile_definitions(<lib> PRIVATE X)` | No |
| `zephyr_library_include_directories(d)` | `target_include_directories(<lib> PRIVATE d)` | No |
| `zephyr_compile_definitions(X)` | `target_compile_definitions(zephyr_interface INTERFACE X)` | Yes, to every Zephyr target |
| `zephyr_include_directories(d)` | `target_include_directories(zephyr_interface INTERFACE d)` | Yes, to every Zephyr target |

The upstream glue uses `zephyr_include_directories` for `inc/` (correct) and
`zephyr_library_compile_definitions` for `DEBUG_PRINT` and
`OSCORE_NVM_SUPPORT`. That is acceptable today: the glue sets no struct-size
macro, so the app and the library both use the header defaults. If Zephyr ever
gets a Kconfig option for a kind-1 macro (for example
`OSCORE_INTERACTIONS_COUNT`), it must use `zephyr_compile_definitions` so that
the app sees it too.

### 3.9 Which keyword do I use?

Ask three questions in this order.

1. **Does a header that consumers compile depend on it** (3.5, 3.6), or does
   consumer code use it? -> `PUBLIC`.
2. **Is it used only by the library's `.c` files or internal headers?** ->
   `PRIVATE`.
3. **Does only the consumer need it, never the library?** -> `INTERFACE`.
   This is rare. It is typical for header-only libraries and for bundles of
   settings (`add_library(x INTERFACE)`).

When unsure, start with `PRIVATE`. Make it `PUBLIC` only when the answer to
question 1 is "yes". The reverse is worse: `PUBLIC` forces your setting on
every consumer.

Applied to this project:

| Setting | Keyword | Reason |
|---|---|---|
| `inc/` include directory | `PUBLIC` | Apps include `edhoc.h` and `oscore.h`. |
| `OSCORE_INTERACTIONS_COUNT`, `OSCORE_SERVER_REPLAY_WINDOW_SIZE`, `OSCORE_MAX_URI_PATH_LEN` | `PUBLIC` | Change the layout of `struct context`, which apps allocate. |
| `OSCORE_MAX_PLAINTEXT_LEN`, `E_OPTIONS_BUFF_MAX_LEN`, `I_OPTIONS_BUFF_MAX_LEN` | `PUBLIC` | Constants in `oscore.h`. |
| `OSCORE_NVM_SUPPORT`, `VLA`, `DEBUG_PRINT` | `PUBLIC` | Change level-2 headers (3.6). |
| EDHOC sizes (`C_I_SIZE`, `CRED_I_SIZE`, `EAD_SIZE`, ...) | `PUBLIC` now, `PRIVATE` after the header split | Only internal headers use them (3.6). |
| `UNIT_TEST` | `PUBLIC` now, test-only after the header split | Only `common/unit_test.h` and tests use it. |
| `MESSAGE_4` | `PRIVATE`, or `PUBLIC` for the test build | Used in `src/`; one test file also branches on it (`edhoc_tests_rfc9529.c`). |
| zcbor include directory | `PUBLIC` now, `PRIVATE` after the header split | Only internal `inc/cbor/*_types.h` include `zcbor_common.h`. |
| Mbed TLS / PSA include directories | `PRIVATE` | Only `src/` includes them. |
| compact25519 include directories | `PRIVATE` | Only `src/common/crypto_wrapper.c` includes them. |
| `MBEDTLS`, `TINYCRYPT`, `COMPACT25519` | `PRIVATE` | Only `src/` tests them. |
| `-Wall -Wextra -Werror` | `PRIVATE` | Warning policy is ours. Do not force it on apps. |
| `-fsanitize=address` (compile and link) | `PUBLIC` | The library and the app must agree. |

### 3.10 The same keywords in `target_link_libraries`

`target_link_libraries(A <scope> B)` uses the same idea.

| Line | Meaning |
|---|---|
| `target_link_libraries(app PRIVATE uoscore-uedhoc)` | `app` links our library. Nothing is passed on, because an executable has no consumers. |
| `target_link_libraries(uoscore-uedhoc PRIVATE zcbor)` | Only our `.c` files and internal headers use zcbor. Apps do not get zcbor's include paths. |
| `target_link_libraries(uoscore-uedhoc PRIVATE MbedTLS::mbedcrypto)` | Only our `.c` files use Mbed TLS headers. |

Rule for static libraries: a `.a` does **not** contain its dependencies.
CMake still adds a `PRIVATE` link dependency of a static library to the
**final link line**, because the linker needs its symbols. It does not add it to
the consumer's **compile line**. CMake handles this for you, including in
exported targets (case B). In a plain Makefile (case C) you must list the
dependency libraries by hand.

### 3.11 Common mistakes

| Mistake | Effect | Fix |
|---|---|---|
| `PRIVATE` on a macro that a consumer-compiled header uses | Silent struct mismatch (3.7) | Make it `PUBLIC`. |
| `PUBLIC` on everything | Consumers receive `-Werror`, internal macros, private include paths. | Use `PRIVATE` unless 3.9 question 1 is "yes". |
| Linking the `.a` by path | No propagation (3.8, case C) | Link the target. |
| `target_include_directories(t dir)` (no keyword) | CMake stops with "called with invalid arguments". | Always write the keyword. |
| `target_link_libraries(t lib)` (no keyword) | Old style. It works but mixes the meanings of the keywords. | Always write the keyword. |
| `include_directories()`, `add_definitions()` | Affects every target below that line, in all scopes. | Use `target_*` with a keyword. |
| Zephyr: `zephyr_library_compile_definitions` for a struct-size macro | The app does not see it. | Use `zephyr_compile_definitions`. |

### 3.12 Target kinds

| Kind | Example | Use |
|---|---|---|
| `STATIC` | `add_library(x STATIC ...)` | Our `.a`. |
| `OBJECT` | `add_library(x OBJECT ...)` | Compile once, reuse objects in several targets. |
| `INTERFACE` | `add_library(x INTERFACE)` | Header-only library or a bundle of usage requirements. No output file. |
| `ALIAS` | `add_library(ns::x ALIAS x)` | Same name whether built in-tree or imported by `find_package`. |
| `IMPORTED` | `add_library(x STATIC IMPORTED)` | A prebuilt library. `find_package` creates one *with* usage requirements (case B). The current Makefile wrapper creates one *without* them (case C); that is the workaround we are removing. |

## 4. Explicit source lists

The Makefile uses `$(wildcard src/*/*.c)`; the Zephyr test/sample CMake files
use `FILE(GLOB ...)`. Both silently pick up whatever is on disk and, in CMake,
only at configure time, so a newly added file is invisible until someone
re-runs CMake.

**Recommended: explicit lists, kept in one file that every front end includes.**
Put them in `cmake/uoscore_uedhoc_sources.cmake`:

```cmake
set(UOSCORE_UEDHOC_COMMON_SOURCES
  src/common/byte_array.c
  src/common/crypto_p256.c
  src/common/crypto_wrapper.c
  src/common/memcpy_s.c
  src/common/print_util.c
)
set(UOSCORE_SOURCES   src/oscore/aad.c ... src/cbor/oscore_info.c)
set(UEDHOC_SOURCES    src/edhoc/associated_data_encode.c ... src/cbor/edhoc_encode_th2.c)
```

Then include it from the top-level `CMakeLists.txt` and, later, from
`zephyr/CMakeLists.txt` (section 11). The groups mirror how the upstream Zephyr
glue already splits the library (common / OSCORE / EDHOC), so OSCORE-only or
EDHOC-only builds become possible.

All paths are relative to the repository root. When you include the list file
from a different directory, resolve them with
`list(TRANSFORM UOSCORE_SOURCES PREPEND "${CMAKE_CURRENT_LIST_DIR}/../")` (the
first argument is the list variable's name) or set a root variable first. The
prototype checked that this explicit list is exactly the 61 `.c` files that
`src/{common,oscore,edhoc,cbor}` contain today.

**If you must glob** (for example for test files), use
`file(GLOB srcs CONFIGURE_DEPENDS tests/*.c)`. `CONFIGURE_DEPENDS` makes the
build tool re-check the directory and re-run CMake if the file set changes.
CMake documents it as best-effort, and it is slower on some filesystems, which
is why explicit lists are preferred for the library.

**Guard against drift:** add a CI check that fails if a `.c` file under `src/`
is not listed, e.g. a small script comparing `ls src/*/*.c` with the list file.
This is what keeps the explicit list from becoming a new source of silent
errors.

### 4.1 The `cmake/` folder

Yes, a top-level `cmake/` folder with `*.cmake` files is a common convention.
Mbed TLS has one (`externals/mbedtls/cmake/MbedTLSConfig.cmake.in`), and Zephyr
has `cmake/modules/`, which contains `extensions.cmake` with all `zephyr_*`
functions.

The rule of thumb:

- `CMakeLists.txt` files describe **targets**: what is built in a directory.
- `cmake/*.cmake` files hold **reusable pieces** that `include()` loads:
  source lists, helper functions, toolchain files, package templates.

Typical files for this project:

| File | Content | Used by |
|---|---|---|
| `cmake/uoscore_uedhoc_sources.cmake` | The explicit source lists | top-level `CMakeLists.txt`, `zephyr/CMakeLists.txt` |
| `cmake/uoscore_uedhoc_vendored_deps.cmake` | Mbed TLS and zcbor targets from `externals/` (section 7.2) | Linux samples only |
| `cmake/arm-none-eabi.cmake` | Toolchain file (section 8) | `-DCMAKE_TOOLCHAIN_FILE=...` |
| `cmake/uoscore-uedhocConfig.cmake.in` | Package config template (section 9.2) | `install(EXPORT ...)` |

Naming conventions CMake itself relies on:

- `Find<Name>.cmake` is a *find module*. `find_package(<Name>)` searches for it
  in `CMAKE_MODULE_PATH`.
- `<Name>Config.cmake` (or `<name>-config.cmake`) is a *package config file*.
  `find_package(<Name> CONFIG)` looks for it.
- Other names are free. Lower-case names with a project prefix avoid clashes.

Two ways to include a file:

```cmake
include(${CMAKE_CURRENT_LIST_DIR}/cmake/uoscore_uedhoc_sources.cmake)  # explicit path

list(APPEND CMAKE_MODULE_PATH ${CMAKE_CURRENT_LIST_DIR}/cmake)          # or search path
include(uoscore_uedhoc_sources)                                          # name without .cmake
```

Prefer the explicit path for files that the Zephyr glue also includes, because
the Zephyr module is processed from another directory
(`${ZEPHYR_CURRENT_MODULE_DIR}/cmake/...`). `include()` runs the file in the
caller's scope, so the `set()` calls in a list file create variables for the
caller. `CMAKE_CURRENT_LIST_DIR` is the directory of the file currently being
processed. It is the right base for relative paths inside an included file.

## 5. Configuration inputs

Today the configuration lives in `makefile_config.mk` as string fragments
(`FEATURES += -DC_I_SIZE=1`, `CRYPTO_ENGINE += -DMBEDTLS`, ...) plus a
caller-supplied `CFLAGS`. In CMake each input becomes a named, typed,
documented **cache variable**. This section first explains what that is. Then
it shows how to use it.

### 5.1 Two kinds of variables

CMake has two kinds of variables.

**Normal variables**

- Created with `set(NAME value)`.
- Exist only while CMake runs the configure step. They are not saved.
- Visible in the current directory scope and in subdirectories added after
  the `set()`. A `function()` gets its own copy.
- Used for internal values, for example the source lists in section 4.

**Cache variables**

- Created with `set(NAME value CACHE <type> "help text")` or with
  `option(NAME "help text" OFF)`.
- **Saved** in the file `CMakeCache.txt` in the build directory.
- **Global**: visible in every directory of the build.
- **User-settable** from outside the `CMakeLists.txt`, with
  `-DNAME=value` on the command line, with a preset, or in `ccmake` or
  `cmake-gui`.
- Used for the inputs a user is allowed to choose.

The word *cache* means "remembered between runs". A build directory remembers
its configuration. You configure once with `-D` values. Every later
`cmake --build` or `cmake -S . -B build` reuses them. You do not repeat the
flags.

Each cache variable has a **type**. The type affects how GUIs show it.

| Type | Meaning | Example |
|---|---|---|
| `BOOL` | ON/OFF. `option()` creates this. | `UOSCORE_UEDHOC_VLA` |
| `STRING` | Free text, numbers, or a choice | `UOSCORE_UEDHOC_CRYPTO_ENGINE` |
| `PATH` / `FILEPATH` | A directory or file | a toolchain or include path |
| `INTERNAL` | Hidden; for CMake's own bookkeeping | (not used by us) |

CMake also stores its own settings in the cache. Examples are
`CMAKE_BUILD_TYPE`, `CMAKE_C_COMPILER` and `CMAKE_TOOLCHAIN_FILE`. That is why
`-DCMAKE_BUILD_TYPE=Release` works the same way as our own options.

### 5.2 The rules, checked with a small experiment

All of these were observed with CMake 3.28. The project contains
`set(SIZE "${DEFAULT_IN_FILE}" CACHE STRING "A size")` and
`option(FEATURE "A feature" OFF)`. Each row is one more `cmake` run on the
**same** build directory.

| Run | `SIZE` result | Rule it shows |
|---|---|---|
| `cmake -DDEFAULT_IN_FILE=3` | 3 | First run: the default in the file is stored. |
| `cmake -DDEFAULT_IN_FILE=4` | **3** | A cache entry is never overwritten by `set(... CACHE ...)`. A changed default does not reach an existing build directory. |
| `cmake -DSIZE=10` | 10 | `-D` on the command line always wins and updates the cache. |
| `cmake -DDEFAULT_IN_FILE=5` | 10 | The value from `-D` is remembered. |
| `cmake` (no arguments) | 10 | Nothing to repeat; the cache supplies it. |
| `set(SIZE 7 CACHE STRING "" FORCE)` in the file | 7 | `FORCE` overwrites the cache. Use rarely; it defeats the user's choice. |
| `cmake -U SIZE -DDEFAULT_IN_FILE=6` | 6 | `-U` deletes the entry; the file's default applies again. |

Two more rules from the same experiment:

- **A normal variable hides a cache variable with the same name.** After
  `set(SIZE 99)`, `${SIZE}` is 99. The cache still holds 10, and
  `$CACHE{SIZE}` reads it. After `unset(SIZE)`, `${SIZE}` is 10 again.
- **`option()` behaves the same:** `-DFEATURE=ON` is stored as
  `FEATURE:BOOL=ON` and kept.

Practical consequences:

- To test a new default, use a **fresh cache**: `cmake --fresh -S . -B build`
  (CMake 3.24+) deletes `CMakeCache.txt` and configures again, while the build
  directory and its objects are kept. `-U NAME` forgets a single entry.
- `rm -rf build`, `cmake --fresh` and `west build -p always` all throw away the
  cache.
- Read the current values with `cmake -L -B build` (`-LH` adds the help
  text), or open `build/CMakeCache.txt`.

### 5.3 Declaring the library's options

```cmake
option(UOSCORE_UEDHOC_DEBUG_PRINT "Enable debug prints" OFF)

set(UOSCORE_UEDHOC_CRYPTO_ENGINE "MBEDTLS" CACHE STRING "Crypto engine")
set_property(CACHE UOSCORE_UEDHOC_CRYPTO_ENGINE PROPERTY STRINGS MBEDTLS TINYCRYPT)

set(UOSCORE_UEDHOC_OSCORE_INTERACTIONS_COUNT "" CACHE STRING
    "Overrides OSCORE_INTERACTIONS_COUNT; empty = header default")
```

- `option()` is for ON/OFF.
- `set(... CACHE STRING ...)` is for choices and numbers.
- `STRINGS` gives `ccmake`/`cmake-gui` a drop-down. It does **not** check
  values given with `-D`.

So validate the values yourself:

```cmake
set(_supported_engines MBEDTLS TINYCRYPT)
if(NOT UOSCORE_UEDHOC_CRYPTO_ENGINE IN_LIST _supported_engines)
  message(FATAL_ERROR "Unsupported UOSCORE_UEDHOC_CRYPTO_ENGINE")
endif()
```

`IN_LIST` takes the *name of a list variable* on its right-hand side. A
literal `"A;B"` there silently never matches (checked with CMake 3.28).

Cross-option rules belong here too. Examples: "suite 2/3 needs MBEDTLS", "OSCORE
or EDHOC must be enabled". This makes the support matrix from section 6 of the
refactoring document executable instead of prose.

### 5.4 Turning inputs into compile definitions

A cache variable is only a value. It does nothing until you attach it to the
target:

```cmake
if(UOSCORE_UEDHOC_DEBUG_PRINT)
  target_compile_definitions(uoscore-uedhoc PUBLIC DEBUG_PRINT)
endif()

if(NOT "${UOSCORE_UEDHOC_OSCORE_INTERACTIONS_COUNT}" STREQUAL "")
  target_compile_definitions(uoscore-uedhoc PUBLIC
    OSCORE_INTERACTIONS_COUNT=${UOSCORE_UEDHOC_OSCORE_INTERACTIONS_COUNT})
endif()

target_compile_definitions(uoscore-uedhoc PRIVATE ${UOSCORE_UEDHOC_CRYPTO_ENGINE})
```

The flow is always the same:

```text
user value (-D, preset, parent project)
   -> cache variable UOSCORE_UEDHOC_X        (stored in CMakeCache.txt)
   -> target_compile_definitions(... X=...)  (PUBLIC or PRIVATE, section 3.9)
   -> -DX=... on the compiler command line
```

Sizes default to "empty = do not define". So the default stays in one place,
the header (`inc/oscore/oscore_interactions.h` here, `inc/edhoc/buffer_sizes.h`
for the EDHOC sizes). Do not duplicate defaults in CMake.

### 5.5 Name your variables with a prefix

Use `UOSCORE_UEDHOC_...`. Cache variables are global. When this project is
added to another project with `add_subdirectory`, an unprefixed name such as
`DEBUG_PRINT` or `VLA` could collide with the parent project's names.

### 5.6 Setting values: command line, presets, parent project, Zephyr

| Who | How |
|---|---|
| Command line | `cmake -S . -B build -DUOSCORE_UEDHOC_VLA=ON` |
| Reusable, named configuration | `CMakePresets.json`, run `cmake --preset <name>` (section 6) |
| Parent project | `set(UOSCORE_UEDHOC_VLA ON CACHE BOOL "")` before `add_subdirectory`. A plain `set(UOSCORE_UEDHOC_VLA ON)` also works: under policy CMP0077 (on by default with `cmake_minimum_required(VERSION 3.13)` or newer) `option()` does not override an existing normal variable. |
| Zephyr | `west build -b <board> -- -DNAME=value` passes `-D` values to CMake. Library options come from Kconfig (section 11). |

Presets replace `makefile_config.mk`: instead of editing a build script, you
pick a named, version-controlled set of option values. Section 6 explains them.

### 5.7 Compiler warnings with generator expressions

Compiler-specific flags go on the target with a generator expression, replacing
the `ifeq ($(findstring cc,$(CC)),cc)` logic in the Makefile:

```cmake
set(_warnings -Wall -Wextra -Wconversion -Wcast-qual)
target_compile_options(uoscore-uedhoc PRIVATE
  "$<$<C_COMPILER_ID:GNU,Clang,AppleClang>:${_warnings}>")

if(UOSCORE_UEDHOC_WARNINGS_AS_ERRORS)
  set_target_properties(uoscore-uedhoc PROPERTIES COMPILE_WARNING_AS_ERROR ON)
endif()
```

`COMPILE_WARNING_AS_ERROR` (CMake 3.24) adds the right flag for the compiler
(`-Werror`, `/WX`, ...), so it needs no compiler check. Anyone can turn it off
for one build with `cmake --compile-no-warning-as-error`, without editing a
file. The property is set only to `ON`: its default comes from the global
`CMAKE_COMPILE_WARNING_AS_ERROR`, and writing `OFF` would override a user who
enabled that.

`UOSCORE_UEDHOC_WARNINGS_AS_ERRORS` affects only the library target. The `ci`
preset sets the global variable `CMAKE_COMPILE_WARNING_AS_ERROR=ON` instead,
which applies to **every** target, including the dependencies and the header
check targets that CMake creates itself (section 16.4). Those generated
targets do not inherit the library's own `COMPILE_WARNING_AS_ERROR`
property.

A generator expression `$<condition:value>` is evaluated when the build files
are generated. It yields `value` if the condition is true, otherwise nothing.

Each generator expression must be **one argument**. Do not break it across
lines and do not put spaces inside it: CMake splits arguments at whitespace, so
`$<cond:-Wall -Wextra>` becomes the two broken arguments `$<cond:-Wall` and
`-Wextra>`. For several flags, put them in a list variable and quote the whole
expression, as above.

Make `-Werror` an option that defaults to `OFF` for consumers (a newer compiler
that adds a warning should not break their build) and `ON` in your own CI
presets. Notice the Makefile's `-Os` filtering and `-g3 -fstack-usage` flags:
optimisation level and debug info should come from `CMAKE_BUILD_TYPE`
(`Debug`, `Release`, `MinSizeRel`) or the consumer, not be hard-coded in the
library. If a flag like `-fstack-usage` is needed for the stack report, add it
only in the CI preset via `CMAKE_C_FLAGS`.

## 6. Presets

Section 5 defined *what* can be configured. This section is about *how* a
configuration of the **standalone** library build is stored and run. Test
configurations of the library are not presets; they are Zephyr test scenarios
in `test/tests.yaml` (section 10.3).

All behaviour described here was checked with CMake 3.28.3, partly with small
experiments. The examples come from the real [CMakePresets.json](CMakePresets.json).

### 6.1 What a preset is

Without presets, a configuration is a command line:

```sh
cmake -S . -B build/ci -G Ninja -DCMAKE_BUILD_TYPE=Debug \
      -DCMAKE_COMPILE_WARNING_AS_ERROR=ON \
      -DCMAKE_VERIFY_INTERFACE_HEADER_SETS=ON
cmake --build build/ci --target all all_verify_interface_header_sets
```

A **preset** gives that command line a name and stores it in a JSON file:

```sh
cmake --workflow --preset ci
```

Key points:

- A preset is **data, not code**. It only fills in what you would otherwise
  type: generator, build directory, `-D` values, targets.
- The options and their meaning stay in `CMakeLists.txt` (section 5). A preset
  only chooses *values*. It cannot create a new option.
- Everyone runs the same configuration by name: developers on the command
  line, CI in `test/ci_scripts/test_library_standalone.sh`.

### 6.2 The presets of this project

The whole file has three configurations:

| Preset | Purpose | Build directory |
|---|---|---|
| `default` | The library with all options at their defaults | `build/default` |
| `legacy-makefile-config` | **Example** of setting options: the values of the former `makefile_config.mk` | `build/legacy-makefile-config` |
| `ci` | The CI check of the standalone build: warnings as errors, API headers self-contained | `build/ci` |

Why so few: the library's option combinations (VLA, MESSAGE_4, TinyCrypt,
ASAN, ...) are tested by Twister with the Zephyr test application, which also
*runs* the tests (section 10.3). Twister does not use the top-level
`CMakeLists.txt`, though, so CI builds the `ci` preset once to check it.

### 6.3 The two files

| File | Purpose | Version control |
|---|---|---|
| `CMakePresets.json` | The project's configurations (6.2) | Committed |
| `CMakeUserPresets.json` | Your personal configurations | **Not** committed (listed in `.gitignore`) |

`CMakeUserPresets.json` is optional and does **not** exist in the repository.
You create it yourself, in the project root, only if you want presets of your
own (6.10). When both files exist, `CMakeUserPresets.json` automatically
includes `CMakePresets.json`, so your presets can inherit from the project's
presets. The other direction is not allowed.

### 6.4 Kinds of presets

A preset file has one list per kind. Each kind belongs to one command:

| Kind | JSON list | Command | Contains | Used here |
|---|---|---|---|---|
| Configure | `configurePresets` | `cmake --preset <name>` | generator, build directory, cache variables | yes |
| Build | `buildPresets` | `cmake --build --preset <name>` | which configure preset, targets | yes |
| Workflow | `workflowPresets` | `cmake --workflow --preset <name>` | configure + build in one command | yes |
| Test | `testPresets` | `ctest --preset <name>` | CTest options | no: tests run with Twister |
| Package | `packagePresets` | `cpack --preset <name>` | CPack options | no |

In this project each configuration has one preset of each used kind, all with
the same name. A build preset uses the build directory of its configure preset,
so configure must run first; otherwise `cmake --build --preset` stops with
"`build/<name>` is not a directory". The workflow preset does both.

### 6.5 File header

```json
{
  "version": 6,
  "cmakeMinimumRequired": { "major": 3, "minor": 28, "patch": 0 },
```

- `version` is the version of the **file format**, not of CMake. Version 6
  (CMake 3.25) is the lowest that has workflow presets. Use the lowest version
  that has what you need.

  | Version | Needs CMake | Adds (selection) |
  |---|---|---|
  | 3 | 3.21 | `condition`, `toolchainFile`, optional `generator` and `binaryDir` |
  | 4 | 3.23 | `include` of other preset files |
  | 6 | 3.25 | **workflow presets**, package presets |
  | 8 | 3.28 | `$schema` field |

- `cmakeMinimumRequired` stops older CMake versions with a clear message. It
  is 3.28, like `cmake_minimum_required()` in `CMakeLists.txt` and like Zephyr.

### 6.6 Configure presets and inheritance

```json
{
  "name": "default",
  "displayName": "Library with default options",
  "generator": "Ninja",
  "binaryDir": "${sourceDir}/build/${presetName}",
  "cacheVariables": {
    "CMAKE_BUILD_TYPE": "Debug"
  }
},
{
  "name": "ci",
  "displayName": "CI check of this build: warnings as errors in all targets, API headers self-contained",
  "inherits": "default",
  "cacheVariables": {
    "CMAKE_COMPILE_WARNING_AS_ERROR": "ON",
    "CMAKE_VERIFY_INTERFACE_HEADER_SETS": "ON"
  }
}
```

| Field | Meaning |
|---|---|
| `name` | Used on the command line. |
| `displayName` | Shown by `cmake --list-presets`. JSON has no comments, so this is the place to say what a preset is for. |
| `generator` | Same as `-G`. |
| `binaryDir` | Same as `-B`. |
| `cacheVariables` | Same as `-D`. Values are strings; `"ON"`/`"OFF"` for options. |
| `inherits` | Copies the fields of another preset. |

**Inheritance.** `ci` and `legacy-makefile-config` inherit from `default`:

```text
default                  Ninja, build/<preset>, Debug
├── legacy-makefile-config   + 14 option values
└── ci                       + warnings as errors, header verification
```

The child gets every field of the parent except `name`, `displayName`,
`description`, `hidden` and `inherits`, and can override any of them.
`cacheVariables` are merged: the child adds variables or overrides single
values. So `ci` builds with `CMAKE_BUILD_TYPE=Debug` from `default` plus its
own two variables.

Two more rules, not used in this file:

- `"inherits": ["a", "b"]` takes fields from several presets. If both set the
  same field, the **first** one wins (checked with an experiment).
- `"hidden": true` makes a preset usable only as a parent: it is not listed,
  and `cmake --preset <name>` fails with "Cannot use hidden preset".

**Macros.** `${sourceDir}` is the project root. `${presetName}` is the name of
the preset being *used*, also when `binaryDir` is inherited. That is why `ci`
builds in `build/ci`, not in `build/default`. Separate build directories mean
separate caches, so configurations never mix (section 5.2). Other macros:
`${sourceParentDir}`, `${hostSystemName}`, `${fileDir}`, `$env{NAME}`.

Not used here but available: `toolchainFile` (same as `-DCMAKE_TOOLCHAIN_FILE`,
section 8), `environment`, `condition` (e.g. only on Linux).

### 6.7 Build presets

```json
"buildPresets": [
  { "name": "default", "configurePreset": "default" },
  { "name": "legacy-makefile-config", "configurePreset": "legacy-makefile-config" },
  { "name": "ci", "configurePreset": "ci", "targets": ["all", "all_verify_interface_header_sets"] }
]
```

- `configurePreset` selects the configure preset and with it the build
  directory.
- `targets` lists what to build. Without it CMake builds `all`. The `ci` build
  preset adds `all_verify_interface_header_sets`, the API header check
  (section 16).
- Command-line arguments win: `cmake --build --preset ci --target clean` builds
  only `clean`.

Other fields (tested): `"jobs": 2`, `"cleanFirst": true` (same as
`--clean-first`), `"verbose": true` (print compiler commands).

### 6.8 Workflow presets

```json
{ "name": "ci", "steps": [
  { "type": "configure", "name": "ci" },
  { "type": "build", "name": "ci" } ] }
```

`cmake --workflow --preset ci` runs the steps in order. CMake prints
`Executing workflow step 1 of 2: configure preset "ci"` and stops at the first
failing step. The first step must be a configure preset; the later steps must
use the same configure preset.

`--fresh` starts with an empty cache. CI uses it, so every CI run is clean:

```sh
# test/ci_scripts/test_library_standalone.sh
cmake -P cmake/check_source_list.cmake
cmake --workflow --preset ci --fresh
```

### 6.9 How preset values interact with the cache

A preset does not replace the cache (section 5.2); it writes into it, like `-D`.
Checked with an experiment, where the preset sets `A=from-preset`:

| Command | Value of `A` afterwards | Rule |
|---|---|---|
| `cmake --preset p` | `from-preset` | The preset writes its `cacheVariables`. |
| `cmake --preset p -DA=other` | `other` | `-D` overrides the preset. |
| `cmake --preset p` (again) | `from-preset` | The preset is applied on **every** run. |
| `cmake build/p` (no preset) | unchanged | Only the cache is used. |
| Preset no longer sets `A`, `cmake --preset p` | still `from-preset` | Removing a variable from a preset does **not** remove it from the cache. |
| `cmake --preset p --fresh` | the default from `CMakeLists.txt` | `--fresh` starts with an empty cache. |

So: to try a value once, add `-D` to `cmake --preset`. To keep it, put it in a
preset. After removing a variable from a preset, use `--fresh`.

### 6.10 Your own presets

Personal configurations go into `CMakeUserPresets.json` in the project root
(git ignores it). They can inherit from the project presets. Tested example:

```json
{
  "version": 6,
  "configurePresets": [
    {
      "name": "my-asan",
      "displayName": "Mine: defaults + AddressSanitizer + debug prints",
      "inherits": "default",
      "cacheVariables": {
        "UOSCORE_UEDHOC_ASAN": "ON",
        "UOSCORE_UEDHOC_DEBUG_PRINT": "ON"
      }
    }
  ],
  "buildPresets": [
    { "name": "my-asan", "configurePreset": "my-asan" }
  ],
  "workflowPresets": [
    { "name": "my-asan", "steps": [
      { "type": "configure", "name": "my-asan" },
      { "type": "build", "name": "my-asan" } ] }
  ]
}
```

`cmake --workflow --preset my-asan` builds into `build/my-asan` with
`-fsanitize=address -DDEBUG_PRINT -std=c17 -g`.

### 6.11 Where does a new configuration go?

| Goal | Where |
|---|---|
| Test the library in another configuration (option combination, board) | A scenario in `test/tests.yaml` (section 10.3). CI runs it with Twister. |
| A configuration for yourself | `CMakeUserPresets.json` (6.10) |
| Show users how to build the standalone library in a configuration | A preset in `CMakePresets.json`, like `legacy-makefile-config` |

### 6.12 Which builds use presets

CMake reads `CMakePresets.json` from the source directory (`-S`). The root
file therefore applies only to the standalone library.

| Build | Configured with |
|---|---|
| Standalone library | the presets of this section |
| Zephyr test | `test/tests.yaml` scenarios (Twister, `west build -T`) or `west build ... -- -D...`; base configuration in `test/prj.conf` |
| Zephyr samples | `west build` and `prj.conf` |
| Linux samples | `cmake -S samples/... -B build`; defaults in `samples/linux_sample.cmake` |

A Zephyr application *can* have its own `CMakePresets.json`, used with
`west build ... -- --preset=<name>`. This was tested with a temporary
`test/CMakePresets.json` that set `BOARD` and two Kconfig options. It is not
the Zephyr way to describe test configurations, though: presets cannot select
boards per variant, run the tests, or check the ztest results. Zephyr uses
`tests.yaml` and Twister for that.

### 6.13 Commands

```sh
cmake --list-presets              # configure presets with their displayName
cmake --list-presets=all          # all kinds

cmake --workflow --preset default         # configure + build
cmake --workflow --preset ci --fresh      # the CI check, with a new cache
cmake --preset default                    # configure only
cmake --preset default -DUOSCORE_UEDHOC_VLA=ON   # with a one-off option
cmake --build --preset default            # build only
cmake --build --preset default --target clean
```

## 7. Dependencies

### 7.1 How it works today

`libuoscore-uedhoc.a` contains **only the library's own code**. The archive
built by the test (`test/build/uoscore_uedhoc/libuoscore-uedhoc.a`) has 61
object files, one per `.c` file in `src/`. It defines no Mbed TLS, PSA, zcbor
or compact25519 symbol. It only *references* them as undefined symbols, for
example `psa_aead_encrypt`, `mbedtls_x509_crt_parse_der_nocopy`,
`zcbor_bstr_decode` and `edsign_sign`.

Every application provides those symbols itself:

- The Linux samples' Makefiles compile `externals/mbedtls/library/*.c`,
  `externals/zcbor/src/*.c` and `externals/compact25519/...` into the app, then
  add `-luoscore-uedhoc`.
- The Zephyr test compiles the same sources into the `app` target.
- Upstream Zephyr links Zephyr's own Mbed TLS (`mbedtls_iface`) and zcbor module.

So you are right: the library is built standalone, and the dependencies are
linked into the application. This is normal for a static library. A `.a` is
just a collection of object files. Neither `ar` nor CMake copies dependency
code into it.

### 7.2 Recommended: declare dependencies as targets

The library says **what** it needs, by target name. Whoever builds the
application decides **where** those targets come from.

```cmake
# In the library's CMakeLists.txt
if(NOT TARGET MbedTLS::mbedx509)
  find_package(MbedTLS 3.6 REQUIRED CONFIG)   # used only if nobody provided it
endif()
if(NOT TARGET zcbor)
  message(FATAL_ERROR "uoscore-uedhoc needs a 'zcbor' target")
endif()

target_link_libraries(uoscore-uedhoc
  PRIVATE MbedTLS::mbedx509 MbedTLS::mbedcrypto zcbor)
```

Notes:

- The link is `PRIVATE`: no header that consumers compile includes a Mbed TLS,
  PSA or zcbor header (section 3.6).
- The include directories of Mbed TLS and zcbor come **from their targets**.
  The library no longer needs `-Iexternals/...` paths.
- Mbed TLS 3.6 ships CMake targets (`MbedTLS::mbedcrypto`, `MbedTLS::mbedx509`,
  `MbedTLS::mbedtls`). zcbor's runtime does not have a standalone CMake target,
  so the application defines a small `zcbor` target (below). Zephyr provides it
  as a module.

A Linux sample migrated to CMake (built and run here, with the real library
and the real `externals/` submodules):

```cmake
cmake_minimum_required(VERSION 3.20)
project(linux_sample LANGUAGES C)

# 1. Dependencies: provided once, by the application
set(ENABLE_PROGRAMS OFF CACHE BOOL "")
set(ENABLE_TESTING OFF CACHE BOOL "")
add_subdirectory(${REPO}/externals/mbedtls mbedtls EXCLUDE_FROM_ALL)

add_library(zcbor STATIC
  ${REPO}/externals/zcbor/src/zcbor_common.c
  ${REPO}/externals/zcbor/src/zcbor_decode.c
  ${REPO}/externals/zcbor/src/zcbor_encode.c)
target_include_directories(zcbor PUBLIC ${REPO}/externals/zcbor/include)
target_compile_definitions(zcbor PUBLIC ZCBOR_CANONICAL)

# 2. The library
add_subdirectory(${REPO} uoscore-uedhoc)

# 3. The app links ONLY the library target
add_executable(app main.c)
target_link_libraries(app PRIVATE uoscore-uedhoc::uoscore-uedhoc)
```

`main.c` referenced `oscore_context_init`, `coap2oscore`, `oscore2coap`,
`edhoc_initiator_run` and `edhoc_responder_run`, so the linker had to resolve
the whole library. The final link command that CMake generated was:

```text
cc main.c.o -o app  uoscore-uedhoc/libuoscore-uedhoc.a
                    mbedtls/library/libmbedx509.a
                    mbedtls/library/libmbedcrypto.a
                    mbedtls/3rdparty/everest/libeverest.a
                    mbedtls/3rdparty/p256-m/libp256m.a
                    libzcbor.a
```

The app named one library. CMake added five dependency archives in the right
order, including Mbed TLS's own internal dependencies (`everest`, `p256m`).
The library archive still contains no dependency code (0 such members).

This is what "the final executable links them" means in practice: the
dependencies are on the **link line**, not in the `.a`. With CMake the
application does not have to list them.

Where the dependency targets come from, per environment:

| Environment | Mbed TLS | zcbor |
|---|---|---|
| Linux samples (CMake) | `add_subdirectory(externals/mbedtls)` or `find_package(MbedTLS)` for a system install | small `zcbor` target from `externals/zcbor/src` |
| Zephyr (after the refactoring) | Zephyr's Mbed TLS module, `mbedtls_iface` | Zephyr's zcbor module |
| Installed library (section 9.2) | `find_package(MbedTLS)` inside the generated package config | to be provided by the consumer |

To avoid repeating the dependency block in every Linux sample, put it in one
file, for example `cmake/uoscore_uedhoc_vendored_deps.cmake`, and `include()`
it from each sample. The library itself never includes that file.

### 7.3 Why not put Mbed TLS into `libuoscore-uedhoc.a`?

A "self-contained" archive is possible. It was built here by merging the six
archives above with a GNU `ar` script:

```text
CREATE libuoscore-uedhoc-bundle.a
ADDLIB uoscore-uedhoc/libuoscore-uedhoc.a
ADDLIB mbedtls/library/libmbedx509.a
ADDLIB mbedtls/library/libmbedcrypto.a
...
SAVE
END
```

A plain `gcc main.c -I inc libuoscore-uedhoc-bundle.a` then linked without any
other library. So it works. But it is **not** the recommended default:

| Problem | Why it matters here |
|---|---|
| Duplicate code | Zephyr apps, and many Linux apps, already link their own Mbed TLS. A second copy inside our `.a` either causes duplicate-symbol errors or, worse, the linker silently uses one copy for some functions and the other copy for others. |
| Frozen configuration | Mbed TLS behaviour depends on its config header (`MBEDTLS_CONFIG_FILE`). The bundle fixes one configuration for every user. The app cannot choose PSA features or a hardware driver. |
| Security updates | An Mbed TLS fix requires a new `uoscore-uedhoc` release. |
| Tooling | CMake has no built-in command to merge archives. The `ar -M` script is GNU binutils specific; macOS needs `libtool -static`. |
| Conflicts with the target model | REFACTROING.MD: the library uses PSA through Zephyr or a user-provided implementation. |

Best practice:

1. The library archive contains only the library. Dependencies are declared
   as targets (7.2).
2. CMake consumers (Linux samples, Zephyr) link the target and get the
   dependencies automatically.
3. Only if a **non-CMake** user needs a single file, add an *optional* target,
   for example `uoscore-uedhoc-bundle`, that merges the archives as above. Name
   it clearly. Never use it in Zephyr builds.

### 7.4 Rule summary

- **Static libraries do not contain their dependencies.** The final executable
  links them.
- With `target_link_libraries(uoscore-uedhoc PRIVATE <dep>)`, CMake puts `<dep>`
  on every consumer's final link line, but not on its compile line
  (section 3.10).
- `PUBLIC` vs `PRIVATE` follows section 3: if a header that consumers compile
  includes the dependency's headers, it is `PUBLIC`.
- Keep `externals/` as fixtures for samples and tests. The library's own
  `CMakeLists.txt` never builds them.

## 8. Toolchains, cross-compiling, sanitizers

Never set `CC`/`AR` in `CMakeLists.txt`. The compiler is a property of the
*invocation*:

```sh
cmake -S . -B build/arm -G Ninja \
      -DCMAKE_TOOLCHAIN_FILE=cmake/arm-none-eabi.cmake \
      -DCMAKE_BUILD_TYPE=MinSizeRel
```

```cmake
# cmake/arm-none-eabi.cmake  (illustrative, not tested here)
set(CMAKE_SYSTEM_NAME Generic)
set(CMAKE_SYSTEM_PROCESSOR arm)
set(CMAKE_C_COMPILER arm-none-eabi-gcc)
set(CMAKE_AR arm-none-eabi-ar)
set(CMAKE_C_FLAGS_INIT "-mcpu=cortex-m3 -mthumb")
# A static library cannot be linked to an executable without a linker script:
set(CMAKE_TRY_COMPILE_TARGET_TYPE STATIC_LIBRARY)
```

This replaces the commented `CC =`, `AR =`, `ARCH = -mtune=...` lines in
`makefile_config.mk`.

For AddressSanitizer, define one option and apply it to every target that must
agree (the library and the test executable), rather than to the library alone:

```cmake
option(UOSCORE_UEDHOC_ASAN "Build with AddressSanitizer" OFF)
if(UOSCORE_UEDHOC_ASAN)
  target_compile_options(uoscore-uedhoc PUBLIC -fsanitize=address -fomit-frame-pointer)
  target_link_options(uoscore-uedhoc PUBLIC -fsanitize=address)
endif()
```

Defined once, this removes the duplicated ASAN block in the Makefile.

Useful side output: `-DCMAKE_EXPORT_COMPILE_COMMANDS=ON` writes
`compile_commands.json` for clangd and static analysers.

## 9. Consuming the library

### 9.1 As a subdirectory (verified)

```cmake
cmake_minimum_required(VERSION 3.20)
project(consumer C)

set(UOSCORE_UEDHOC_OSCORE_INTERACTIONS_COUNT 5 CACHE STRING "")   # consumer chooses values only
add_subdirectory(path/to/uoscore-uedhoc lib)

add_executable(app main.c)
target_link_libraries(app PRIVATE uoscore-uedhoc::uoscore-uedhoc)
```

This was built and run with the prototype (section 3.7): the app received
`-DOSCORE_INTERACTIONS_COUNT=5` from the library target, and
`sizeof(struct context)` was 856 bytes in both the app and the library.
Section 3.8 compares this with an installed package and with linking the `.a`
by path.

The consumer contains no source list, no `-D` fragment and no `make` call;
that is the "authoritative target" in practice.

### 9.2 As an installed package

```cmake
install(TARGETS uoscore-uedhoc EXPORT uoscore-uedhocTargets
        ARCHIVE DESTINATION ${CMAKE_INSTALL_LIBDIR})
install(DIRECTORY inc/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR}/uoscore-uedhoc)
install(EXPORT uoscore-uedhocTargets NAMESPACE uoscore-uedhoc::
        DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/uoscore-uedhoc)
# plus a Config.cmake via CMakePackageConfigHelpers; version checks for
# find_package(uoscore-uedhoc 3.2) need write_basic_package_version_file() and
# therefore a project VERSION (see section 2.2)
```

Consumers then call `find_package(uoscore-uedhoc)` and link the same alias name.
This is optional; do it when you need non-CMake or binary distribution.
Use `$<BUILD_INTERFACE:...>` and `$<INSTALL_INTERFACE:...>` around include paths
so build-tree and install-tree locations are not mixed up.

### 9.3 With FetchContent

```cmake
include(FetchContent)
FetchContent_Declare(uoscore-uedhoc GIT_REPOSITORY <url> GIT_TAG <tag>)
FetchContent_MakeAvailable(uoscore-uedhoc)
```

Equivalent to 8.1 with the source downloaded for you.

## 10. Tests

**Decision: the only test project is the Zephyr application in `test/`.**
There is no separate host test suite and no CTest. One test app covers both
the host and real MCUs, because Zephyr builds the same sources for any board.

The test app uses Zephyr's ztest framework (`CONFIG_ZTEST=y` in
`test/prj.conf`, `ZTEST(uoscore_uedhoc, ...)` in `test/main.c`).

### 10.1 Building for different boards

The board is chosen with `-b`. Give each board its own build directory with
`-d`, so the caches (section 5.2) never mix:

```sh
cd test
west build -b native_sim              -d build/native_sim               # host
west build -b native_sim/native/64    -d build/native_sim_64            # 64-bit host
west build -b nrf52840dk/nrf52840     -d build/nrf52840dk               # MCU
west build -b nrf9160dk/nrf9160       -d build/nrf9160dk                # MCU (used by the ROM report)
```

| Board kind | How to run the tests |
|---|---|
| `native_sim` | `west build -d build/native_sim -t run` executes them on the host. CI uses this. |
| QEMU boards, e.g. `qemu_cortex_m3` | `west build -d <dir> -t run` starts the emulator. |
| Real hardware | `west flash -d <dir>`, then read the ztest output on the board's serial console. |

`west build -p always` (pristine) deletes the build directory's cache first.
It replaces the `rm -rf build/` in the current `test/README.MD`.

### 10.2 Board-specific settings

Zephyr merges extra configuration by file name, so the test `CMakeLists.txt`
does not need board `if()` blocks:

| File | Applied when |
|---|---|
| `test/prj.conf` | always |
| `test/boards/<board>.conf` | building for `<board>` (for example a larger stack on a small MCU) |
| `test/boards/<board>.overlay` | devicetree changes for `<board>` |

### 10.3 Test configurations

The library options are Kconfig symbols of the module (section 11).
`test/prj.conf` holds the default test configuration. Zephyr has three ways to
build a variant; they build on each other:

| Level | Mechanism | Example |
|---|---|---|
| One build | `-D` after `--` | `west build -b native_sim -d build/vla_msg4 -- -DCONFIG_UOSCORE_UEDHOC_VLA=y -DCONFIG_UEDHOC_MESSAGE_4=y` |
| A reusable variant | Kconfig fragment file | `test/vla_msg4.conf` with the two lines, used with `-- -DEXTRA_CONF_FILE=vla_msg4.conf` |
| The whole matrix | `tests.yaml` + **Twister** | below |

**Twister is Zephyr's mechanism for test configurations.** A YAML file in the
application directory lists named *scenarios*; each scenario is a set of extra
Kconfig values or CMake arguments, plus the boards it may run on. Twister
builds every scenario for every selected board, runs it (on `native_sim`,
QEMU, or real hardware), and parses the ztest output. In Zephyr itself, all
1329 test suites under `tests/` use such a file; 446 of them use
`extra_configs` and 303 `extra_args`. Zephyr has no `CMakePresets.json` of its
own (apart from a sysbuild helper that forwards an application's presets).

The file is `tests.yaml` (older names, still accepted: `testcase.yaml`,
`sample.yaml`). This project's file, [test/tests.yaml](test/tests.yaml):

```yaml
# Test configurations, run by Twister. See README.MD.

common:
  tags: [uoscore, uedhoc]
  platform_allow:
    - native_sim
    - native_sim/native/64
    - nrf52840dk/nrf52840
    - nrf9160dk/nrf9160
    - kit_pse84_ai/pse846gps2dbzc4a/m33
  integration_platforms:  # the boards CI uses (--integration)
    - native_sim
    - native_sim/native/64

tests:
  uoscore_uedhoc.default: {}

  uoscore_uedhoc.vla_message_4:
    extra_configs:
      - CONFIG_UOSCORE_UEDHOC_VLA=y
      - CONFIG_UEDHOC_MESSAGE_4=y

  # TinyCrypt is not in Zephyr: zcbor and Mbed TLS come from externals/ too.
  uoscore_uedhoc.tinycrypt:
    extra_conf_files:
      - overlay-external-deps.conf
    extra_configs:
      - CONFIG_UOSCORE_UEDHOC_TINYCRYPT=y

  # AddressSanitizer exists only on the posix (native_sim) boards.
  uoscore_uedhoc.asan:
    arch_allow: posix
    extra_configs:
      - CONFIG_ASAN=y

  uoscore_uedhoc.asan.vla:
    arch_allow: posix
    extra_configs:
      - CONFIG_ASAN=y
      - CONFIG_UOSCORE_UEDHOC_VLA=y

  uoscore_uedhoc.asan.message_4:
    arch_allow: posix
    extra_configs:
      - CONFIG_ASAN=y
      - CONFIG_UEDHOC_MESSAGE_4=y

  uoscore_uedhoc.asan.vla_message_4:
    arch_allow: posix
    extra_configs:
      - CONFIG_ASAN=y
      - CONFIG_UOSCORE_UEDHOC_VLA=y
      - CONFIG_UEDHOC_MESSAGE_4=y

  # Debug output (overlay-debug.conf) is only built, never run.
  uoscore_uedhoc.debug:
    build_only: true
    extra_conf_files:
      - overlay-debug.conf
```

How to read it:

- **Scenario names** (`uoscore_uedhoc.vla_message_4`, ...) are what Twister
  reports and what `-T` selects. Dots group them: `uoscore_uedhoc.asan.*` are
  the AddressSanitizer variants.
- **`extra_configs`** are Kconfig values added to `prj.conf` for that scenario.
- **`common`** applies to all scenarios. Lists in `common` and in a scenario
  are *added together* (a scenario cannot shorten a list from `common`), so
  the boards are listed once, in `common`.
- **`platform_allow`** lists the boards a scenario may be built for.
  **`integration_platforms`** is the subset used with `--integration`, which is
  what CI runs: all eight scenarios on `native_sim` and `native_sim/native/64`,
  16 configurations.
- **`arch_allow: posix`** limits a scenario to boards of the posix
  architecture, here the two `native_sim` boards. `CONFIG_ASAN` exists only
  there, so the ASAN scenarios need it; with `-p nrf9160dk/nrf9160` they are
  filtered out instead of failing. (ASAN on `native_sim/native/64` was checked:
  49/49 with VLA and MESSAGE_4.)
- **`build_only: true`** builds a scenario and never runs it. Used for
  `uoscore_uedhoc.debug` (below).
- **`extra_conf_files`** adds Kconfig fragment files on top of `prj.conf`
  (it becomes `EXTRA_CONF_FILE`).
- **`tags`** must be a YAML list (`[a, b]` or one item per line); this
  Zephyr version rejects `"uoscore uedhoc"`.
- **No `timeout`**: Twister's default limit of 60 s per test run applies. A run
  takes 1-3 s. The limit was only exceeded when the machine was overloaded by
  parallel builds with an old Ninja (see "Build time and Ninja" below).

Commands, run from the repository root:

```sh
west twister -T test --integration                         # what CI runs
west twister -T test -p native_sim                         # all scenarios, one board
west twister -T test -p nrf9160dk/nrf9160 --build-only     # MCU builds, no hardware
west build -p always -b native_sim -d build/vla -T test/uoscore_uedhoc.vla_message_4
```

`-T` takes the application directory for `west twister`, and
`<app dir>/<scenario>` for `west build`. Twister writes builds and reports to
`twister-out/` (git-ignored).

Verified here with Zephyr 4.5.0-rc2:

- `--integration --dry-run` selects the 16 configurations above; with
  `-p nrf52840dk/nrf52840 -p nrf9160dk/nrf9160` it selects 8 (the four
  non-ASAN scenarios per board).
- A first prototype (five `native_sim` scenarios) passed 5 of 5 configurations,
  245 of 245 test cases, in about 6 minutes with `-j 8`.
- `-p nrf52840dk/nrf52840 -p nrf9160dk/nrf9160 --build-only` built all six
  allowed board configurations without errors.
- The binaries of `uoscore_uedhoc.default` and
  `uoscore_uedhoc.asan.vla_message_4` pass 49/49 tests when run directly (1 s
  and 3 s).
- A full `--integration` run with the final file was not completed here. The
  earlier attempt ran with `-j 8` and Ninja 1.11.1; each build then took
  about 600 s and the runs hit the 60 s default timeout (see "Build time and
  Ninja").
- Without debug output, `uoscore_uedhoc.default` builds in 45 s (with warnings
  as errors, as Twister builds), passes 49/49, and prints 208 lines instead of
  8,196.
- `west build -T test/uoscore_uedhoc.debug` builds with
  `CONFIG_UOSCORE_DEBUG=y` and `CONFIG_UEDHOC_DEBUG=y` from
  `overlay-debug.conf`.
- `west build -T test/uoscore_uedhoc.asan.vla_message_4` produced a
  `zephyr/.config` with all three options set.
- Twister prints `ERROR - .../main.c: Found a test that does not start with
  test_` for ztest names such as `t1_oscore`. It is a naming-convention check
  and does not fail the run.

Compared with the former `test/ci_scripts/test_build_options.sh`, Twister
runs every scenario, reports each failure by name, and exits with a non-zero
code if any scenario fails (the script did not fail fast, see section 2 of the
refactoring document). It names each configuration, writes reports (`twister.json`, and
JUnit XML in `twister.xml`), and adds boards by listing them. Adding
`nrf9160dk/nrf9160` to `platform_allow` builds the scenarios for that board as
well. A board that is not a simulator is only built, not run, unless a board
is attached and Twister is called with `--device-testing`. `--build-only`
skips running everywhere.

**Build time and Ninja.** Twister builds `-j` configurations at the same
time, each with `cmake --build`. To share the CPUs, Twister runs a GNU make
*job server*: a pool of job tokens that every build must take from. Ninja
joins such a pool only from version 1.13. With Ubuntu's Ninja 1.11.1, every
build ran all its jobs: with `-j 8` on 20 threads, up to ~176 compilers ran at
once, and each build took about 600 s instead of 45 s.

The dev container therefore installs Ninja 1.13.2 from PyPI
(`.devcontainer/scripts/install_zephyr.sh`). Measured with 12 one-second jobs
under a job server with 4 slots:

| Ninja | Time | Job server obeyed |
|---|---|---|
| 1.11.1 (Ubuntu 24.04) | 1.0 s | no |
| 1.13.2 (PyPI) | 3.0 s | yes |

A detail: Twister uses the newer *named-pipe* form of the job server only if
GNU make >= 4.4 is installed as well. Ubuntu 24.04 has make 4.3, so Twister
uses the older *file-descriptor* form. The PyPI build of Ninja is a Kitware
variant that accepts both forms; with it on `PATH`, Twister's own job server
limited the builds as expected (3.0 s in the test above). A plain upstream
Ninja 1.13 accepts only the named-pipe form.

Without the new Ninja (an older container), limit each build by hand:
`export CMAKE_BUILD_PARALLEL_LEVEL=2` and choose `-j` so that `-j` × 2 is
about `nproc`.

**CI runs and development runs.** Twister has several ways to choose what runs:

| Mechanism | Effect | Used here |
|---|---|---|
| `integration_platforms` + `--integration` | CI uses a small board list; without `--integration`, all `platform_allow` boards | yes |
| `build_only: true` | Built, never run | `uoscore_uedhoc.debug` |
| `tags` + `-t <tag>` / `-e <tag>` | Select or exclude scenarios by tag | tags only |
| `slow: true` + `--enable-slow` | Run only when asked | no |

What is **not** idiomatic is a scenario that only exists for development, for
example to run the tests with debug output. In Zephyr, `tests.yaml` describes
what is tested; `prj.conf` stays quiet; development options are Kconfig
fragments such as `overlay-debug.conf` that a developer adds to any build
(Zephyr itself has 14 `*debug*.conf` files in `samples/` and `tests/`, e.g.
`samples/net/sockets/echo_server/overlay-debug.conf`). If such a fragment
should not break, CI builds it with `build_only: true`, as Zephyr does in
`tests/misc/test_build/tests.yaml`. This project does exactly that:

```sh
# development: one scenario with debug output
west build -p always -b native_sim -d build/vla -T test/uoscore_uedhoc.vla_message_4 \
    -- -DEXTRA_CONF_FILE=overlay-debug.conf
west build -d build/vla -t run
```

**Presets** (section 6) also work for a Zephyr application (6.12), but they are
not the idiomatic choice there: they cannot select boards per scenario, run
tests or parse ztest results.

### 10.4 What the standalone CMake build is for

The top-level CMake project (sections 2-9) builds the library and the Linux
samples. It does not build tests. Twister never uses it (Zephyr builds the
library through `zephyr/CMakeLists.txt`), so CI checks it separately with
`test/ci_scripts/test_library_standalone.sh`: the source list, the `ci` preset
(warnings as errors, API headers self-contained), and the Linux samples.
Behaviour is tested only by the Zephyr test app.

## 11. Zephyr

### 11.1 How Zephyr uses CMake

`west build` runs CMake for you, using Zephyr's toolchain and board settings.
An application `CMakeLists.txt` begins with:

```cmake
cmake_minimum_required(VERSION 3.20.0)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(my_app)
target_sources(app PRIVATE src/main.c)
```

`app` is Zephyr's application target. Configuration comes from **Kconfig**
(`prj.conf`, board files): every `CONFIG_FOO=y` becomes a CMake variable
`CONFIG_FOO` that you can test with `if(CONFIG_FOO)`, and a C macro.
`west build -- -DNAME=value` passes `-D` values to CMake just as in section 5.

### 11.2 What upstream Zephyr does today

Upstream has *two* parts, in *two repositories*:

| Piece | Where | Content |
|---|---|---|
| This library | `zephyrproject-rtos/uoscore-uedhoc` (a fork of the Fraunhofer-AISEC project), pinned in Zephyr's `west.yml` and checked out at `modules/lib/uoscore-uedhoc` | `src/`, `inc/`, and `zephyr/module.yml` containing `cmake-ext: True` and `kconfig-ext: True` |
| Zephyr glue | Zephyr tree: `modules/uoscore-uedhoc/` | `CMakeLists.txt`, `Kconfig`, `uoscore_nvm.c` |

`cmake-ext: True` means "the CMake and Kconfig files for this module live
inside the **Zephyr** repository". The glue then:

- is active only when `CONFIG_UOSCORE` or `CONFIG_UEDHOC` is set;
- creates three libraries with `zephyr_library_named()`:
  `uoscore_uedhoc_common`, `uoscore`, `uedhoc`;
- lists every source file by hand with `zephyr_library_sources(...)`, using
  `${ZEPHYR_CURRENT_MODULE_DIR}/src`;
- translates Kconfig to definitions with
  `zephyr_library_compile_definitions(...)` (`MBEDTLS` always,
  `DEBUG_PRINT` from `CONFIG_UOSCORE_DEBUG`/`CONFIG_UEDHOC_DEBUG`,
  `OSCORE_NVM_SUPPORT` from `CONFIG_UOSCORE_NVM_SUPPORT`);
- links `mbedtls_iface` and selects the required `PSA_WANT_*` options in
  Kconfig (P-256, AES-CCM, HMAC, SHA-256), and depends on `ZCBOR` and
  `ZCBOR_CANONICAL`;
- adds a Zephyr-owned `uoscore_nvm.c` that implements `nvm_read_ssn` /
  `nvm_write_ssn` with the Zephyr settings subsystem.

Key observations for this project: the library repository cannot currently
change its own source list, options or Zephyr integration without a matching
pull request in the Zephyr repository; and the Zephyr build supports a
**subset** of the configuration space (PSA/Mbed TLS, P-256; no TinyCrypt or
compact25519, and the EDHOC buffer sizes are header defaults, not Kconfig
options). A comparison of the glue's file list with the library showed
`src/common/crypto_p256.c` (called from `crypto_wrapper.c`) was not listed.
Treat that as an unverified drift risk, since Zephyr was not built here; it is
exactly what a hand-maintained duplicate list produces.

### 11.3 The two ways to integrate (see the refactoring document for the recommendation)

**Option A: keep `cmake-ext: True`.** The Zephyr repository keeps owning the
glue. To remove the duplicate list, the Zephyr glue would `include()` a list
file shipped by the library:

```cmake
# modules/uoscore-uedhoc/CMakeLists.txt  (in the Zephyr repository)
include(${ZEPHYR_CURRENT_MODULE_DIR}/cmake/uoscore_uedhoc_sources.cmake)
zephyr_library_sources(${UOSCORE_UEDHOC_COMMON_SOURCES})
```

The source list becomes library-owned, but options, Kconfig and NVM glue still
need Zephyr-side pull requests.

**Option B: library owns the glue.** Change `zephyr/module.yml` to the default
(`build: {cmake: zephyr, kconfig: zephyr/Kconfig}`, or simply omit the keys)
and add `zephyr/CMakeLists.txt`, `zephyr/Kconfig` and `zephyr/uoscore_nvm.c` to
the library repository, while Zephyr deletes `modules/uoscore-uedhoc/` in the
same pull request that moves the pinned revision:

```cmake
# zephyr/CMakeLists.txt  (in this repository; untested sketch)
if(CONFIG_UOSCORE OR CONFIG_UEDHOC)
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/uoscore_uedhoc_sources.cmake)
  set(_root ${CMAKE_CURRENT_LIST_DIR}/..)

  zephyr_include_directories(${_root}/inc)

  zephyr_library_named(uoscore_uedhoc_common)
  zephyr_library_compile_definitions(MBEDTLS)
  zephyr_library_compile_definitions_ifdef(CONFIG_UEDHOC_DEBUG DEBUG_PRINT)
  list(TRANSFORM UOSCORE_UEDHOC_COMMON_SOURCES PREPEND ${_root}/)
  zephyr_library_sources(${UOSCORE_UEDHOC_COMMON_SOURCES})
  zephyr_library_link_libraries_ifdef(CONFIG_MBEDTLS_BUILTIN mbedtls_iface)

  # same pattern for uoscore (CONFIG_UOSCORE) and uedhoc (CONFIG_UEDHOC)
endif()
```

Zephyr API names used above (`zephyr_library_named`, `zephyr_library_sources`,
`zephyr_library_compile_definitions`, `zephyr_library_link_libraries_ifdef`,
`ZEPHYR_CURRENT_MODULE_DIR`) appear in the current upstream glue, and
`zephyr_library_compile_definitions_ifdef` is defined in Zephyr's
`cmake/modules/extensions.cmake` on `main`. Check them against the Zephyr
version you target.

In both options Zephyr uses `zephyr_library*`, **not** the plain
`add_library`/`target_*` commands from the standalone build, because
`zephyr_library` automatically applies Zephyr's include paths, board flags and
Kconfig-generated headers. The two front ends therefore share the **data**
(the source lists and the option names and meanings) and not the target
definition itself. This is why the shared list file in section 4 is the
critical piece.

Mapping between the two front ends:

| Meaning | Standalone CMake | Zephyr |
|---|---|---|
| Debug prints | `UOSCORE_UEDHOC_DEBUG_PRINT` | `CONFIG_UEDHOC_DEBUG` / `CONFIG_UOSCORE_DEBUG` |
| OSCORE NVM | `UOSCORE_UEDHOC_NVM_SUPPORT` | `CONFIG_UOSCORE_NVM_SUPPORT` |
| TinyCrypt add-on | `UOSCORE_UEDHOC_TINYCRYPT` | `CONFIG_UOSCORE_UEDHOC_TINYCRYPT` (external deps only) |
| VLA, message_4 | `UOSCORE_UEDHOC_VLA`, `UOSCORE_UEDHOC_MESSAGE_4` | `CONFIG_UOSCORE_UEDHOC_VLA`, `CONFIG_UEDHOC_MESSAGE_4` |
| Buffer sizes | `UOSCORE_UEDHOC_C_I_SIZE` etc. | none today; add Kconfig options if needed |

### 11.4 Testing through the same glue

The tests currently compile `externals/mbedtls/library/*.c` into the test app and
use a private config header, so they do not exercise what a Zephyr user gets.
Instead, register this repository as an extra module from the test
`CMakeLists.txt` before `find_package(Zephyr)`:

```cmake
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_LIST_DIR}/..)   # before find_package(Zephyr)
```

With Option B this loads the repository's own `zephyr/CMakeLists.txt` and
`zephyr/Kconfig`; then `prj.conf` just says `CONFIG_UEDHOC=y` and
`CONFIG_UOSCORE=y`, and the test links the real module. With Option A the
installed Zephyr's in-tree glue is used instead, which is a useful
compatibility check but cannot test unreleased glue changes.

### 11.5 Rules of thumb in Zephyr CMake

- Application code: `target_sources(app PRIVATE ...)`; library code in a
  module: `zephyr_library_sources(...)`.
- Don't use `ExternalProject_Add` or harvest flags with
  `zephyr_get_compile_options_for_lang_as_string`; link a Zephyr library target.
- Don't call global `include_directories()` / `add_definitions()` (the existing
  test `CMakeLists.txt` does); use the target-scoped forms.
- Guard everything with the Kconfig symbol so an unselected module costs
  nothing.

## 12. Makefile-to-CMake mapping

| Makefile / current setup | CMake |
|---|---|
| `make` | `cmake -S . -B build && cmake --build build` |
| `make PREFIX=out` (output dir) | `-B out` |
| `make clean` | `cmake --build build --target clean`, or delete the build directory |
| `CC=...`, `AR=...` | `-DCMAKE_C_COMPILER=...`, toolchain file |
| `CFLAGS=...` from outside | `-DCMAKE_C_FLAGS=...` for generic flags; named `UOSCORE_UEDHOC_*` options for library features |
| `makefile_config.mk` (`FEATURES += -D...`) | cache options + `CMakePresets.json` |
| `$(wildcard src/*/*.c)` | explicit list in `cmake/uoscore_uedhoc_sources.cmake` |
| `C_INCLUDES += -Iinc` | `target_include_directories(... PUBLIC inc)` |
| `-DCRYPTO_ENGINE` | `UOSCORE_UEDHOC_CRYPTO_ENGINE` |
| `-std=c11` | `C_STANDARD 17` + `C_EXTENSIONS OFF` (`-std=c17`, as Zephyr) |
| `-MMD -MP -MF` | automatic |
| warning blocks per compiler | generator expressions on `target_compile_options` |
| duplicated `FEATURES`/ASAN lines | one option, one place |
| `ExternalProject_Add(... make ...)` + imported archive | `target_link_libraries(app PRIVATE uoscore-uedhoc::uoscore-uedhoc)` |
| Default to TinyCrypt when no engine is set | option with explicit default and validation |

Note: the Makefile `-Os` filtering (`FILTERED_CFLAGS`) has no direct
counterpart; it removes `-Os` from the externally supplied `CFLAGS` so that
`OPT` can win. In CMake, rely on `CMAKE_BUILD_TYPE`.

## 13. Pitfalls and checklist

- **Global commands**: `include_directories`, `add_definitions`,
  `link_libraries`, `set(CMAKE_C_FLAGS ...)` in library code affect everything
  below them. Use `target_*`.
- **`PUBLIC` leaks**: only options that must be visible to consumers should be
  `PUBLIC`. If a macro is not used in a public header, make it `PRIVATE`.
  Likewise, do not leak `-Werror` publicly.
- **Stale cache**: changing a default in `CMakeLists.txt` does not change an
  existing build directory's cache value. Use a fresh binary directory (or
  `cmake -U 'UOSCORE_UEDHOC_*'`) when testing.
- **In-source builds**: do not run `cmake .` in the source tree. Always use
  `-B`. Consider failing configure if `CMAKE_SOURCE_DIR` equals
  `CMAKE_BINARY_DIR`.
- **Same options, two builds**: the library and its consumers must be built
  with the same configuration. Public definitions (section 3) enforce this;
  global flags do not.
- **Explicit lists drift**: add a CI check that compares the list with the
  file tree.
- **Zephyr is not "just CMake"**: `CONFIG_*` values come from Kconfig, and
  `zephyr_library*` commands differ from `add_library`; see section 11.

Acceptance checklist for the migration:

- [ ] `cmake -S . -B build/x && cmake --build build/x` works with no other
      step and writes nothing outside `build/x`.
- [ ] `git status` is clean after building.
- [ ] The consumer sample/test links one target and has no source list for the
      library.
- [ ] Changing `OSCORE_INTERACTIONS_COUNT` changes `sizeof(struct context)`
      equally in the consumer and in the library.
- [ ] Internal headers are not reachable from the public include directory.
- [ ] Each preset in the support matrix is built in CI.
- [ ] Adding a `.c` file without listing it fails CI.

## 14. Command cheat sheet

```sh
cmake -S . -B build/host -G Ninja                    # configure
cmake -S . -B build/host -DUOSCORE_UEDHOC_VLA=ON      # set an option
cmake -L -B build/host                                # list cache variables (-LH adds help text)
cmake --build build/host -j                           # build
cmake --build build/host --target uoscore-uedhoc -v   # one target, show commands
cmake --preset <name> && cmake --build --preset <name>   # presets: section 6.13
cmake --workflow --preset <name> --fresh            # configure + build, new cache
cmake --fresh -S . -B build/host                     # reconfigure with a new cache
cmake -S . -B build/host --compile-no-warning-as-error
cmake --build --preset ci          # includes all_verify_interface_header_sets
cmake --install build/host --prefix /tmp/stage        # install
cmake -S . -B build/host -U 'UOSCORE_UEDHOC_*'        # forget cached option values
cmake -S . -B build/host -DCMAKE_EXPORT_COMPILE_COMMANDS=ON
west build -b native_sim -d build/native_sim test     # Zephyr tests, host
west build -d build/native_sim -t run                 # run them
west build -b <board> -d build/<board> -p always test # Zephyr tests, MCU, fresh cache
west flash -d build/<board>                           # flash to the board
```

## 15. Further reading

- CMake buildsystem concepts (targets, usage requirements):
  <https://cmake.org/cmake/help/latest/manual/cmake-buildsystem.7.html>
- Presets: <https://cmake.org/cmake/help/latest/manual/cmake-presets.7.html>
- Generator expressions:
  <https://cmake.org/cmake/help/latest/manual/cmake-generator-expressions.7.html>
- Toolchain files:
  <https://cmake.org/cmake/help/latest/manual/cmake-toolchains.7.html>
- Zephyr modules (including `cmake-ext`/`kconfig-ext`):
  <https://docs.zephyrproject.org/latest/develop/modules.html>
- Upstream Zephyr glue for this library:
  <https://github.com/zephyrproject-rtos/zephyr/tree/main/modules/uoscore-uedhoc>
- What changed in each CMake version:
  <https://cmake.org/cmake/help/latest/release/index.html>

## 16. CMake 3.21-3.28 features used in this project

The minimum was raised from 3.20 to 3.28 to match Zephyr. Every CMake file of
the project was then checked for features from 3.21-3.28 that simplify it or
make it safer. Each adopted item was verified by building (CMake 3.28.3).

### 16.1 Adopted

| Feature | Since | Where | What it replaces / improves |
|---|---|---|---|
| `<PROJECT-NAME>_IS_TOP_LEVEL` | 3.21 | `CMakeLists.txt` | `uoscore_uedhoc_IS_TOP_LEVEL` replaces comparing `CMAKE_CURRENT_SOURCE_DIR` with `CMAKE_SOURCE_DIR`. The project-specific name stays correct even if a subproject calls `project()` later. |
| Policy CMP0128 + `C_STANDARD 17` | 3.22 | `CMakeLists.txt` | `C_EXTENSIONS OFF` is now honoured. With `C_STANDARD 17` the library compiles as `-std=c17`, the same as Zephyr (before: no flag, i.e. GNU C17 with extensions). The former CI presets (all option combinations) built cleanly in strict C17. |
| `FILE_SET HEADERS` | 3.23 | `CMakeLists.txt` | A header set with the API headers (`edhoc.h`, `oscore.h`) and base directory `inc/` replaces `target_include_directories()`. CMake wraps the base directory in `$<BUILD_INTERFACE>` itself, and the set is ready for `install(TARGETS ... FILE_SET HEADERS)`. |
| `LINK_LIBRARIES_ONLY_TARGETS` | 3.23 | `zephyr/CMakeLists.txt` | In Zephyr, the module runs before the application creates the dependency targets, so a configure-time `if(TARGET ...)` check is impossible. This property checks the names at generate time: a misspelled `UOSCORE_UEDHOC_DEPENDENCY_TARGETS` entry stops the build with "... is not a target" instead of a late `cannot find -l<name>` from the linker (tested). |
| `COMPILE_WARNING_AS_ERROR`, `--compile-no-warning-as-error` | 3.24 | `CMakeLists.txt`, `samples/linux_sample.cmake` | Replaces the compiler-specific `-Werror` generator expression and the samples' hard-coded `-Werror`. Works for every compiler; users can opt out per build. |
| `VERIFY_INTERFACE_HEADER_SETS` | 3.24 | `ci` preset | `CMAKE_VERIFY_INTERFACE_HEADER_SETS=ON` creates `all_verify_interface_header_sets`. For each API header it generates a `.c` file that contains only `#include "<header>"` and compiles it, so a header that uses a type without including its definition fails CI (tested by breaking `edhoc.h`). The `ci` build preset builds this target. See section 16.4. |
| `cmake --fresh` | 3.24 | CI script, docs | Configure with a new cache without deleting the build directory. |
| `add_subdirectory(... SYSTEM)` | 3.25 | `cmake/uoscore_uedhoc_vendored_deps.cmake` | Mbed TLS include directories reach consumers as `-isystem` instead of `-I`, so warnings inside Mbed TLS headers cannot fail our `-Werror` build. |
| `block()` / `endblock()` | 3.25 | `cmake/uoscore_uedhoc_vendored_deps.cmake` | Gives the helper variable `_ext` its own scope (`PROPAGATE` exports the results) instead of `set()` ... `unset()`. |
| Workflow presets (schema 6) | 3.25 | `CMakePresets.json`, `test/ci_scripts/test_library_standalone.sh` | `cmake --workflow --preset ci --fresh` configures and builds in one command, with a new cache. See section 6.8. |
| `cmakeMinimumRequired` 3.28 in presets, `CMAKE_BUILD_TYPE` in the base preset | 3.21+ | `CMakePresets.json` | Presets state the same minimum as the CMake files. The build type is explicit in presets; the `Debug` fallback in `CMakeLists.txt` covers plain `cmake -S . -B`. |

### 16.2 Considered, not adopted

| Feature | Since | Why not now |
|---|---|---|
| Header set with **all** of `inc/` and verification | 3.23/3.24 | Measured: 13 of 88 headers are not self-contained. `edhoc/int_encode_decode.h` uses `bool` without including `<stdbool.h>` (error). Six more hand-written headers and six generated `inc/cbor/` headers use `struct byte_array`, `struct suite`, `enum info_label` or `struct zcbor_string` without including their declaration (warnings). Do it with the header split, when internal headers move to a `PRIVATE` header set; fix the generated ones through the generator, not by hand. |
| `install(TARGETS ... FILE_SET HEADERS)`, package export | 3.23 | Install/export rules are a separate, deferred step. The header set prepares for it. |
| `FetchContent` with `SOURCE_DIR`, `OVERRIDE_FIND_PACKAGE` (3.24), `SYSTEM` (3.25), `EXCLUDE_FROM_ALL` (3.28) for Mbed TLS | 3.24-3.28 | Would let `find_package(MbedTLS)` resolve to the submodule. `add_subdirectory(... EXCLUDE_FROM_ALL SYSTEM)` already gives the same result with less machinery. Revisit if users want "system Mbed TLS if found, else submodule". |
| `$<LINK_GROUP:RESCAN,...>`, `$<LINK_LIBRARY:...>` | 3.24 | No circular dependencies between our static libraries; CMake's link order works. |
| `$<COMPILE_ONLY:...>` | 3.27 | Every consumer that needs Mbed TLS headers also needs to link it. |
| Preset schema 7/8 (`$penv` in includes, `$schema`) | 3.27/3.28 | No use for either; schema 6 is the lowest version with workflows. |
| C++20 module scanning (CMP0155) | 3.28 | The project has no C++20 code; the C++ in the Linux samples is unaffected. |
| A `cmake_minimum_required` in `zephyr/CMakeLists.txt` | | Zephyr sets 3.28 before processing modules; a module file must not reset policies. |

### 16.3 Policy changes that matter here

Raising the minimum sets policies CMP0121-CMP0155 to NEW. For this project:

- **CMP0128** changed the compile flags of the library (see 16.1). It was
  resolved by setting `C_STANDARD 17` explicitly.
- **CMP0126** (`set(CACHE)` keeps an existing normal variable) and **CMP0124**
  (loop variables are restored after `foreach`) only make the existing code
  more predictable.
- All others concern features the project does not use (MSVC, Xcode, CUDA,
  Python finders, `exec_program`, ...). The library's compile commands were
  compared before and after for the `default` preset: the same 61 sources and
  the same definitions; the only differences are the added `-std=c17` and the
  four Mbed TLS include directories moving from `-I` to `-isystem`.

### 16.4 The header check in detail

**The problem it solves.** A header is *self-contained* if a `.c` file whose
only line is `#include "<header>"` compiles cleanly. A header that is not
self-contained still works when every `.c` file happens to include the missing
headers first. The order of `#include` lines then matters, and a new user who
includes the header first gets a confusing error (section 7 of
REFACTROING.MD).

**Step 1: declare the headers (a header set).** In `CMakeLists.txt`:

```cmake
target_sources(uoscore-uedhoc PUBLIC
  FILE_SET HEADERS BASE_DIRS ${UOSCORE_UEDHOC_INCLUDE_DIR} FILES ${_api_headers})
```

`_api_headers` is `inc/edhoc.h` and `inc/oscore.h`. `PUBLIC` means they belong
to the library's interface; the base directory `inc/` becomes a public include
directory.

**Step 2: turn on verification.** `CMAKE_VERIFY_INTERFACE_HEADER_SETS=ON`
(set by the `ci` preset) gives every target with a `PUBLIC` or `INTERFACE`
header set the property `VERIFY_INTERFACE_HEADER_SETS`. When it generates the
build files, CMake then creates:

- one object library `uoscore-uedhoc_verify_interface_header_sets`, with one
  generated `.c` file per header, and
- a target `all_verify_interface_header_sets` that builds all such libraries.

The generated files in `build/ci/uoscore-uedhoc_verify_interface_header_sets/`
are:

```c
/* edhoc.h.c */
#include <edhoc.h> // IWYU pragma: associated
```

```c
/* oscore.h.c */
#include <oscore.h> // IWYU pragma: associated
```

That line is the whole file. (The comment is for the include-what-you-use tool
and has no effect on compilation.)

**Step 3: compile them.** The `ci` build preset lists
`all_verify_interface_header_sets` in `targets`, so
`cmake --workflow --preset ci` compiles both files. The command is (paths
shortened):

```text
cc -Iinc -x c -g -Werror -c .../uoscore-uedhoc_verify_interface_header_sets/edhoc.h.c
```

- `-Iinc` comes from the library's **public** usage requirements: the check
  target links the library, like a consumer would (section 3.4). The library's
  `PRIVATE` settings, such as its `-Wall -Wextra ...` and its own
  `COMPILE_WARNING_AS_ERROR`, are not used.
- `-Werror` comes from the global `CMAKE_COMPILE_WARNING_AS_ERROR=ON` of the
  `ci` preset. Without it, only compile **errors** fail the check.
- Nothing is linked; an object file that compiles is the pass condition.

**What it catches** (both tested by adding a test header to the check):

| Header problem | GCC result | Fails the check? |
|---|---|---|
| uses `bool` without `#include <stdbool.h>` | error: unknown type name `bool` | yes |
| uses `struct suite *` without its declaration | warning: `struct suite` declared inside parameter list | **only with** `CMAKE_COMPILE_WARNING_AS_ERROR=ON`; without it, the check passed |

A first version of the `ci` preset set only `UOSCORE_UEDHOC_WARNINGS_AS_ERRORS`
(the library's own property) and therefore missed the second case. The preset
now sets the global variable; the full `ci` build, Mbed TLS and zcbor
included, builds with `-Werror` without a single warning.

**What it does not catch.** It checks only the headers in the header set, today
`edhoc.h` and `oscore.h`. Through their `#include`s, it also covers the 15
headers they pull in (section 3.5). The 13 internal headers in `inc/` that are
not self-contained (section 7 of REFACTROING.MD) are outside the set and are
not checked until the header split puts every header in a header set.
