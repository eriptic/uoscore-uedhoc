# SPDX-License-Identifier: Apache-2.0 OR MIT

# Build the third-party code in externals/ as CMake targets, for the Linux
# samples, the Zephyr test and a standalone development build.
#
# The uoscore-uedhoc library itself never compiles these sources. It only
# links the targets that the build environment provides (see
# UOSCORE_UEDHOC_DEPENDENCY_TARGETS in the top-level CMakeLists.txt and in
# zephyr/CMakeLists.txt). Real applications normally provide their own
# Mbed TLS and zcbor instead, e.g. Zephyr's modules.
#
# Functions:
#   uoscore_uedhoc_add_vendored_deps()
#     Plain CMake build. Creates the targets
#       MbedTLS::mbedcrypto, MbedTLS::mbedx509  (Mbed TLS's own CMake project)
#       zcbor, compact25519, tinycrypt
#
#   uoscore_uedhoc_add_zephyr_vendored_deps(MBEDTLS_CONFIG_FILE <header>)
#     Zephyr build (call after find_package(Zephyr)). Compiles the same code
#     with Zephyr's compiler flags and creates the targets
#       uoscore_uedhoc_vendored_mbedtls, uoscore_uedhoc_vendored_zcbor,
#       uoscore_uedhoc_vendored_compact25519, uoscore_uedhoc_vendored_tinycrypt

include_guard(GLOBAL)

get_filename_component(UOSCORE_UEDHOC_EXTERNALS_DIR
  "${CMAKE_CURRENT_LIST_DIR}/../externals" ABSOLUTE)

# block() keeps the helper variable _ext local; PROPAGATE exports the lists.
block(PROPAGATE
    UOSCORE_UEDHOC_ZCBOR_SOURCES UOSCORE_UEDHOC_ZCBOR_INCLUDE_DIRS
    UOSCORE_UEDHOC_COMPACT25519_SOURCES UOSCORE_UEDHOC_COMPACT25519_INCLUDE_DIRS
    UOSCORE_UEDHOC_TINYCRYPT_SOURCES UOSCORE_UEDHOC_TINYCRYPT_INCLUDE_DIRS)
set(_ext "${UOSCORE_UEDHOC_EXTERNALS_DIR}")

set(UOSCORE_UEDHOC_ZCBOR_SOURCES
  ${_ext}/zcbor/src/zcbor_common.c
  ${_ext}/zcbor/src/zcbor_decode.c
  ${_ext}/zcbor/src/zcbor_encode.c
  ${_ext}/zcbor/src/zcbor_print.c
)
set(UOSCORE_UEDHOC_ZCBOR_INCLUDE_DIRS ${_ext}/zcbor/include)

set(UOSCORE_UEDHOC_COMPACT25519_SOURCES
  ${_ext}/compact25519/src/compact_ed25519.c
  ${_ext}/compact25519/src/compact_wipe.c
  ${_ext}/compact25519/src/compact_x25519.c
  ${_ext}/compact25519/src/c25519/c25519.c
  ${_ext}/compact25519/src/c25519/ed25519.c
  ${_ext}/compact25519/src/c25519/edsign.c
  ${_ext}/compact25519/src/c25519/f25519.c
  ${_ext}/compact25519/src/c25519/fprime.c
  ${_ext}/compact25519/src/c25519/sha512.c
)
set(UOSCORE_UEDHOC_COMPACT25519_INCLUDE_DIRS
  ${_ext}/compact25519/src
  ${_ext}/compact25519/src/c25519
)

set(UOSCORE_UEDHOC_TINYCRYPT_SOURCES
  ${_ext}/tinycrypt/lib/source/aes_decrypt.c
  ${_ext}/tinycrypt/lib/source/aes_encrypt.c
  ${_ext}/tinycrypt/lib/source/cbc_mode.c
  ${_ext}/tinycrypt/lib/source/ccm_mode.c
  ${_ext}/tinycrypt/lib/source/cmac_mode.c
  ${_ext}/tinycrypt/lib/source/ctr_mode.c
  ${_ext}/tinycrypt/lib/source/ctr_prng.c
  ${_ext}/tinycrypt/lib/source/ecc.c
  ${_ext}/tinycrypt/lib/source/ecc_dh.c
  ${_ext}/tinycrypt/lib/source/ecc_dsa.c
  ${_ext}/tinycrypt/lib/source/ecc_platform_specific.c
  ${_ext}/tinycrypt/lib/source/hmac.c
  ${_ext}/tinycrypt/lib/source/hmac_prng.c
  ${_ext}/tinycrypt/lib/source/sha256.c
  ${_ext}/tinycrypt/lib/source/utils.c
)
set(UOSCORE_UEDHOC_TINYCRYPT_INCLUDE_DIRS ${_ext}/tinycrypt/lib/include)
endblock()

function(_uoscore_uedhoc_add_small_deps prefix)
  add_library(${prefix}zcbor STATIC EXCLUDE_FROM_ALL ${UOSCORE_UEDHOC_ZCBOR_SOURCES})
  target_include_directories(${prefix}zcbor SYSTEM PUBLIC ${UOSCORE_UEDHOC_ZCBOR_INCLUDE_DIRS})
  # The generated CBOR code in src/cbor requires canonical encoding.
  target_compile_definitions(${prefix}zcbor PUBLIC ZCBOR_CANONICAL)

  add_library(${prefix}compact25519 STATIC EXCLUDE_FROM_ALL
    ${UOSCORE_UEDHOC_COMPACT25519_SOURCES})
  target_include_directories(${prefix}compact25519 SYSTEM PUBLIC
    ${UOSCORE_UEDHOC_COMPACT25519_INCLUDE_DIRS})

  add_library(${prefix}tinycrypt STATIC EXCLUDE_FROM_ALL ${UOSCORE_UEDHOC_TINYCRYPT_SOURCES})
  target_include_directories(${prefix}tinycrypt SYSTEM PUBLIC
    ${UOSCORE_UEDHOC_TINYCRYPT_INCLUDE_DIRS})
endfunction()

function(uoscore_uedhoc_add_vendored_deps)
  if(TARGET zcbor)
    return()
  endif()

  _uoscore_uedhoc_add_small_deps("")

  if(NOT TARGET MbedTLS::mbedcrypto)
    set(ENABLE_PROGRAMS OFF CACHE BOOL "Build Mbed TLS programs")
    set(ENABLE_TESTING OFF CACHE BOOL "Build Mbed TLS tests")
    set(MBEDTLS_FATAL_WARNINGS OFF CACHE BOOL "Mbed TLS warnings as errors")
    # SYSTEM: consumers get the Mbed TLS headers as system includes, so
    # warnings in them do not fail builds with warnings as errors.
    add_subdirectory(${UOSCORE_UEDHOC_EXTERNALS_DIR}/mbedtls
      ${CMAKE_BINARY_DIR}/externals/mbedtls EXCLUDE_FROM_ALL SYSTEM)
  endif()
endfunction()

function(uoscore_uedhoc_add_zephyr_vendored_deps)
  cmake_parse_arguments(arg "" "MBEDTLS_CONFIG_FILE" "" ${ARGN})
  if(NOT arg_MBEDTLS_CONFIG_FILE)
    message(FATAL_ERROR "uoscore_uedhoc_add_zephyr_vendored_deps: MBEDTLS_CONFIG_FILE is required")
  endif()
  if(NOT TARGET zephyr_interface)
    message(FATAL_ERROR "uoscore_uedhoc_add_zephyr_vendored_deps: call it after find_package(Zephyr)")
  endif()

  set(prefix uoscore_uedhoc_vendored_)
  _uoscore_uedhoc_add_small_deps(${prefix})

  file(GLOB mbedtls_sources CONFIGURE_DEPENDS
    ${UOSCORE_UEDHOC_EXTERNALS_DIR}/mbedtls/library/*.c)
  add_library(${prefix}mbedtls STATIC EXCLUDE_FROM_ALL ${mbedtls_sources})
  get_filename_component(config_dir ${arg_MBEDTLS_CONFIG_FILE} DIRECTORY)
  get_filename_component(config_name ${arg_MBEDTLS_CONFIG_FILE} NAME)
  target_include_directories(${prefix}mbedtls SYSTEM PUBLIC
    ${UOSCORE_UEDHOC_EXTERNALS_DIR}/mbedtls/include
    ${config_dir})
  target_include_directories(${prefix}mbedtls PRIVATE
    ${UOSCORE_UEDHOC_EXTERNALS_DIR}/mbedtls/library)
  # PUBLIC so that every user of the Mbed TLS headers sees the same configuration.
  target_compile_definitions(${prefix}mbedtls PUBLIC
    MBEDTLS_CONFIG_FILE="${config_name}")

  foreach(dep mbedtls zcbor compact25519 tinycrypt)
    target_link_libraries(${prefix}${dep} PRIVATE zephyr_interface)
  endforeach()
endfunction()
