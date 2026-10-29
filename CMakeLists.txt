# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Standalone build of the uoscore-uedhoc static library.
#
#   cmake -S . -B build/default -G Ninja
#   cmake --build build/default          -> build/default/libuoscore-uedhoc.a
#
# or with a preset from CMakePresets.json:
#
#   cmake --preset default && cmake --build --preset default
#
# Other CMake projects use the library with add_subdirectory() and link the
# target uoscore-uedhoc::uoscore-uedhoc. Zephyr uses zephyr/CMakeLists.txt,
# which shares the source list in cmake/uoscore_uedhoc_sources.cmake.

cmake_minimum_required(VERSION 3.28)
project(uoscore_uedhoc LANGUAGES C)

include(${CMAKE_CURRENT_LIST_DIR}/cmake/uoscore_uedhoc_sources.cmake)

# uoscore_uedhoc_IS_TOP_LEVEL (set by project()) is true when this is the
# project given to cmake -S, false when another project includes it.
if(uoscore_uedhoc_IS_TOP_LEVEL AND NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# ------------------------------------------------------------------------------
# Configuration inputs
# ------------------------------------------------------------------------------

option(UOSCORE_UEDHOC_TINYCRYPT
  "Also use TinyCrypt, preferred over Mbed TLS where crypto_wrapper.c supports it (deprecated)" OFF)
option(UOSCORE_UEDHOC_COMPACT25519
  "Use compact25519 for X25519 and Ed25519 (EDHOC suites 0 and 1)" ON)
option(UOSCORE_UEDHOC_WITH_OSCORE "Build the OSCORE part" ON)
option(UOSCORE_UEDHOC_WITH_EDHOC "Build the EDHOC part" ON)
option(UOSCORE_UEDHOC_DEBUG_PRINT "Print debug information (DEBUG_PRINT)" OFF)
option(UOSCORE_UEDHOC_NVM_SUPPORT
  "Persist the OSCORE sender sequence number; the application implements nvm_write_ssn()/nvm_read_ssn() (OSCORE_NVM_SUPPORT)" OFF)
option(UOSCORE_UEDHOC_VLA "Size buffers at runtime with variable length arrays (VLA)" OFF)
option(UOSCORE_UEDHOC_MESSAGE_4 "Use EDHOC message_4 (MESSAGE_4)" OFF)
option(UOSCORE_UEDHOC_UNIT_TEST "Make static functions visible to unit tests (UNIT_TEST)" OFF)
option(UOSCORE_UEDHOC_WARNINGS_AS_ERRORS "Treat compiler warnings in the library as errors" OFF)
option(UOSCORE_UEDHOC_ASAN "Build with AddressSanitizer (also applied to consumers)" OFF)
option(UOSCORE_UEDHOC_VENDORED_DEPS
  "Build Mbed TLS, zcbor, compact25519 and TinyCrypt from externals/" ${uoscore_uedhoc_IS_TOP_LEVEL})

# Buffer sizes and limits. Empty means: keep the default from the header.
set(UOSCORE_UEDHOC_SIZE_OPTIONS
  # inc/edhoc/buffer_sizes.h
  EAD_SIZE C_I_SIZE C_R_SIZE ID_CRED_I_SIZE ID_CRED_R_SIZE CRED_I_SIZE
  CRED_R_SIZE SUITES_I_SIZE
  # inc/oscore.h
  OSCORE_MAX_PLAINTEXT_LEN E_OPTIONS_BUFF_MAX_LEN I_OPTIONS_BUFF_MAX_LEN
  K_SSN_NVM_STORE_INTERVAL F_NVM_MAX_WRITE_FAILURE
  # inc/oscore/*.h
  OSCORE_INTERACTIONS_COUNT OSCORE_SERVER_REPLAY_WINDOW_SIZE
  OSCORE_MAX_URI_PATH_LEN
)
foreach(size IN LISTS UOSCORE_UEDHOC_SIZE_OPTIONS)
  set(UOSCORE_UEDHOC_${size} "" CACHE STRING "Value of ${size}; empty keeps the header default")
endforeach()

# ------------------------------------------------------------------------------
# Validation
# ------------------------------------------------------------------------------

if(NOT UOSCORE_UEDHOC_WITH_OSCORE AND NOT UOSCORE_UEDHOC_WITH_EDHOC)
  message(FATAL_ERROR "Enable UOSCORE_UEDHOC_WITH_OSCORE, UOSCORE_UEDHOC_WITH_EDHOC or both")
endif()
foreach(size IN LISTS UOSCORE_UEDHOC_SIZE_OPTIONS)
  set(value "${UOSCORE_UEDHOC_${size}}")
  if(NOT value STREQUAL "" AND NOT value MATCHES "^[0-9]+$")
    message(FATAL_ERROR "UOSCORE_UEDHOC_${size}='${value}' is not a non-negative integer")
  endif()
endforeach()

# ------------------------------------------------------------------------------
# Dependencies
# ------------------------------------------------------------------------------
# The library links its dependencies by target name. Whoever builds it provides
# the targets: UOSCORE_UEDHOC_VENDORED_DEPS=ON builds them from externals/;
# otherwise define them before add_subdirectory() (Mbed TLS may also be found
# with find_package). To use other target names, set
# UOSCORE_UEDHOC_DEPENDENCY_TARGETS to the full list.

if(UOSCORE_UEDHOC_VENDORED_DEPS)
  include(${CMAKE_CURRENT_LIST_DIR}/cmake/uoscore_uedhoc_vendored_deps.cmake)
  uoscore_uedhoc_add_vendored_deps()
endif()

if(NOT DEFINED UOSCORE_UEDHOC_DEPENDENCY_TARGETS)
  # Mbed TLS is always needed: src/common/crypto_p256.c and the X.509 code use
  # PSA and Mbed TLS also when TinyCrypt is enabled.
  if(NOT TARGET MbedTLS::mbedcrypto)
    find_package(MbedTLS 3.6 CONFIG REQUIRED)
  endif()
  set(UOSCORE_UEDHOC_DEPENDENCY_TARGETS zcbor MbedTLS::mbedx509 MbedTLS::mbedcrypto)
  if(UOSCORE_UEDHOC_TINYCRYPT)
    list(APPEND UOSCORE_UEDHOC_DEPENDENCY_TARGETS tinycrypt)
  endif()
  if(UOSCORE_UEDHOC_COMPACT25519)
    list(APPEND UOSCORE_UEDHOC_DEPENDENCY_TARGETS compact25519)
  endif()
endif()

foreach(dep IN LISTS UOSCORE_UEDHOC_DEPENDENCY_TARGETS)
  if(NOT TARGET ${dep})
    message(FATAL_ERROR
      "uoscore-uedhoc needs the CMake target '${dep}'. Define it before adding "
      "this project, or configure with -DUOSCORE_UEDHOC_VENDORED_DEPS=ON.")
  endif()
endforeach()

# ------------------------------------------------------------------------------
# The library
# ------------------------------------------------------------------------------

set(_sources ${UOSCORE_UEDHOC_COMMON_SOURCES})
if(UOSCORE_UEDHOC_WITH_OSCORE)
  list(APPEND _sources ${UOSCORE_SOURCES})
endif()
if(UOSCORE_UEDHOC_WITH_EDHOC)
  list(APPEND _sources ${UEDHOC_SOURCES})
endif()

add_library(uoscore-uedhoc STATIC ${_sources})
add_library(uoscore-uedhoc::uoscore-uedhoc ALIAS uoscore-uedhoc)

# The header set lists the public API headers. Its base directory inc/ becomes
# the PUBLIC include directory (all of inc/ is reachable until the internal
# headers move out, see CMAKE_TUTORIAL.md section 3.5). With
# CMAKE_VERIFY_INTERFACE_HEADER_SETS=ON (CI presets), the target
# all_verify_interface_header_sets checks that each API header is
# self-contained: for every header it compiles a generated .c file that
# contains only #include "<header>".
set(_api_headers)
if(UOSCORE_UEDHOC_WITH_OSCORE)
  list(APPEND _api_headers ${UOSCORE_UEDHOC_INCLUDE_DIR}/oscore.h)
endif()
if(UOSCORE_UEDHOC_WITH_EDHOC)
  list(APPEND _api_headers ${UOSCORE_UEDHOC_INCLUDE_DIR}/edhoc.h)
endif()
target_sources(uoscore-uedhoc PUBLIC
  FILE_SET HEADERS BASE_DIRS ${UOSCORE_UEDHOC_INCLUDE_DIR} FILES ${_api_headers})

# C17 without GNU extensions (-std=c17), the same as Zephyr's default and
# minimum (CONFIG_STD_C17, CONFIG_GNU_C_EXTENSIONS=n). Consumers need at least C17.
target_compile_features(uoscore-uedhoc PUBLIC c_std_17)
set_target_properties(uoscore-uedhoc PROPERTIES
  C_STANDARD 17
  C_STANDARD_REQUIRED ON
  C_EXTENSIONS OFF)

# Macros used by headers in inc/ are PUBLIC, so that consumers compile the
# headers with the same values as the library. Today all of inc/ is reachable
# by consumers; see CMAKE_TUTORIAL.md, section 3.
foreach(flag IN ITEMS DEBUG_PRINT VLA UNIT_TEST)
  if(UOSCORE_UEDHOC_${flag})
    target_compile_definitions(uoscore-uedhoc PUBLIC ${flag})
  endif()
endforeach()
if(UOSCORE_UEDHOC_NVM_SUPPORT)
  target_compile_definitions(uoscore-uedhoc PUBLIC OSCORE_NVM_SUPPORT)
endif()
foreach(size IN LISTS UOSCORE_UEDHOC_SIZE_OPTIONS)
  if(NOT "${UOSCORE_UEDHOC_${size}}" STREQUAL "")
    target_compile_definitions(uoscore-uedhoc PUBLIC ${size}=${UOSCORE_UEDHOC_${size}})
  endif()
endforeach()

# Macros used only by the library's .c files.
target_compile_definitions(uoscore-uedhoc PRIVATE MBEDTLS)
foreach(flag IN ITEMS TINYCRYPT COMPACT25519 MESSAGE_4)
  if(UOSCORE_UEDHOC_${flag})
    target_compile_definitions(uoscore-uedhoc PRIVATE ${flag})
  endif()
endforeach()

# No public header includes a dependency's header, so the links are PRIVATE.
# For a static library CMake still adds them to the consumer's link line.
target_link_libraries(uoscore-uedhoc PRIVATE ${UOSCORE_UEDHOC_DEPENDENCY_TARGETS})

set(_gnu_warnings
  -Wall -Wextra -Wconversion -Wcast-qual -Waddress -Waggregate-return
  -Wformat -Wformat-nonliteral -Wformat-security -Winit-self
  -Wmissing-include-dirs -Wunreachable-code -Wwrite-strings -Wpointer-arith
  -Wno-multichar -Wno-parentheses -Wno-type-limits -Wno-unused-parameter)
set(_clang_warnings
  -Wall -Wextra -Wconversion -Wcast-qual -Wshadow -Wmissing-prototypes
  -Wmissing-noreturn -Wno-missing-braces)
target_compile_options(uoscore-uedhoc PRIVATE
  "$<$<C_COMPILER_ID:GNU>:${_gnu_warnings}>"
  "$<$<C_COMPILER_ID:Clang,AppleClang>:${_clang_warnings}>"
)
# COMPILE_WARNING_AS_ERROR adds the right flag for each compiler and can be
# overridden with cmake --compile-no-warning-as-error. It is only set to ON
# here, so a global CMAKE_COMPILE_WARNING_AS_ERROR=ON still applies otherwise.
if(UOSCORE_UEDHOC_WARNINGS_AS_ERRORS)
  set_target_properties(uoscore-uedhoc PROPERTIES COMPILE_WARNING_AS_ERROR ON)
endif()

if(UOSCORE_UEDHOC_ASAN)
  target_compile_options(uoscore-uedhoc PUBLIC -fsanitize=address -fno-omit-frame-pointer)
  target_link_options(uoscore-uedhoc PUBLIC -fsanitize=address)
endif()
