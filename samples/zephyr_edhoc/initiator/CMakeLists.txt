# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.28)

# Use this repository's Zephyr module (zephyr/). prj.conf enables it with
# CONFIG_UEDHOC=y and CONFIG_UOSCORE_UEDHOC_EXTERNAL_DEPS=y, so the library links
# the dependencies listed here, built below from externals/. An application
# that uses Zephyr's zcbor and Mbed TLS modules needs neither of these.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_LIST_DIR}/../../..)
set(UOSCORE_UEDHOC_DEPENDENCY_TARGETS
  uoscore_uedhoc_vendored_mbedtls
  uoscore_uedhoc_vendored_zcbor
  uoscore_uedhoc_vendored_compact25519
)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(initiator)

set(REPO_DIR ${CMAKE_CURRENT_LIST_DIR}/../../..)

include(${REPO_DIR}/cmake/uoscore_uedhoc_vendored_deps.cmake)
uoscore_uedhoc_add_zephyr_vendored_deps(
  MBEDTLS_CONFIG_FILE ${REPO_DIR}/test/mbedtls_config_uoscore_uedhoc.h
)

target_sources(app PRIVATE
  src/main.c
  src/_entropy.c
  ${REPO_DIR}/samples/common/sock_ipv6.c
)

target_include_directories(app PRIVATE
  $ENV{ZEPHYR_BASE}/subsys/net/ip
  ${REPO_DIR}/samples/common
  ${REPO_DIR}/test_vectors
)

# main.c uses the PRINT_* macros
target_compile_definitions(app PRIVATE DEBUG_PRINT)
