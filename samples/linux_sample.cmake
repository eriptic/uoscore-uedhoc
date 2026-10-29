# SPDX-License-Identifier: Apache-2.0 OR MIT
#
# Shared setup for the Linux samples. Each sample is a standalone CMake
# project that includes this file, for example:
#
#   cmake -S samples/linux_oscore/client -B build/samples/linux_oscore_client
#   cmake --build build/samples/linux_oscore_client
#
# The sample links only the uoscore-uedhoc target; CMake adds the library's
# dependencies (Mbed TLS, zcbor, compact25519) to the link line.

include_guard(GLOBAL)

get_filename_component(UOSCORE_UEDHOC_REPO_DIR "${CMAKE_CURRENT_LIST_DIR}/.." ABSOLUTE)

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  set(CMAKE_BUILD_TYPE Debug CACHE STRING "Build type" FORCE)
endif()

# Third-party code from externals/, built as separate targets.
include(${UOSCORE_UEDHOC_REPO_DIR}/cmake/uoscore_uedhoc_vendored_deps.cmake)
uoscore_uedhoc_add_vendored_deps()

# Library configuration for the samples; override with -D<name>=<value>.
# main.cpp uses the PRINT_* macros, which need DEBUG_PRINT.
set(UOSCORE_UEDHOC_DEBUG_PRINT ON CACHE BOOL "Print debug information (DEBUG_PRINT)")
add_subdirectory(${UOSCORE_UEDHOC_REPO_DIR} uoscore-uedhoc)

add_library(cantcoap STATIC EXCLUDE_FROM_ALL
  ${UOSCORE_UEDHOC_EXTERNALS_DIR}/cantcoap/cantcoap.cpp)
target_include_directories(cantcoap SYSTEM PUBLIC ${UOSCORE_UEDHOC_EXTERNALS_DIR}/cantcoap)

add_library(linux_sample_sockets STATIC EXCLUDE_FROM_ALL
  ${CMAKE_CURRENT_LIST_DIR}/common/sock.c
  ${CMAKE_CURRENT_LIST_DIR}/common/sock_ipv4.c
  ${CMAKE_CURRENT_LIST_DIR}/common/sock_ipv6.c)
target_include_directories(linux_sample_sockets PUBLIC ${CMAKE_CURRENT_LIST_DIR}/common)
target_compile_definitions(linux_sample_sockets PUBLIC LINUX_SOCKETS)

add_library(linux_sample_test_vectors STATIC EXCLUDE_FROM_ALL
  ${UOSCORE_UEDHOC_REPO_DIR}/test_vectors/edhoc_test_vectors_rfc9529.c
  ${UOSCORE_UEDHOC_REPO_DIR}/test_vectors/oscore_test_vectors.c)
target_include_directories(linux_sample_test_vectors PUBLIC ${UOSCORE_UEDHOC_REPO_DIR}/test_vectors)
target_link_libraries(linux_sample_test_vectors PUBLIC uoscore-uedhoc::uoscore-uedhoc)

# uoscore_uedhoc_linux_sample(<name>)
#   Creates the executable <name> from src/main.cpp and src/_entropy.c of the
#   calling sample directory.
function(uoscore_uedhoc_linux_sample name)
  add_executable(${name}
    ${CMAKE_CURRENT_SOURCE_DIR}/src/main.cpp
    ${CMAKE_CURRENT_SOURCE_DIR}/src/_entropy.c)
  target_link_libraries(${name} PRIVATE
    uoscore-uedhoc::uoscore-uedhoc
    linux_sample_sockets
    linux_sample_test_vectors
    cantcoap)
  target_compile_options(${name} PRIVATE -Wall)
  set_target_properties(${name} PROPERTIES COMPILE_WARNING_AS_ERROR ON)
endfunction()
