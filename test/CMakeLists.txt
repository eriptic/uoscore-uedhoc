# SPDX-License-Identifier: Apache-2.0
#
# Zephyr ztest application for uoscore-uedhoc.
#
#   west build -b native_sim -d build/native_sim
#   west build -d build/native_sim -t run
#
# The library is built by this repository's Zephyr module (zephyr/), exactly as
# in an application. Its options are Kconfig symbols, see prj.conf and
# zephyr/Kconfig, e.g. west build -b native_sim -- -DCONFIG_UOSCORE_UEDHOC_VLA=y

cmake_minimum_required(VERSION 3.28)

# Use this repository's module, even if the west manifest also contains one.
list(APPEND ZEPHYR_EXTRA_MODULES ${CMAKE_CURRENT_LIST_DIR}/..)

# By default the library uses Zephyr's zcbor and Mbed TLS modules; the module
# builds compact25519 from externals/. With
# CONFIG_UOSCORE_UEDHOC_EXTERNAL_DEPS=y (overlay-external-deps.conf) the
# library links these targets instead, created below from externals/.
set(UOSCORE_UEDHOC_DEPENDENCY_TARGETS
  uoscore_uedhoc_vendored_mbedtls
  uoscore_uedhoc_vendored_zcbor
  uoscore_uedhoc_vendored_compact25519
  uoscore_uedhoc_vendored_tinycrypt
)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(auto_test)

target_sources(app PRIVATE
  main.c
  mocks/nvm.c
  edhoc_integration_tests/edhoc_tests_kid.c
  edhoc_integration_tests/edhoc_tests_rfc9529.c
  edhoc_integration_tests/exporter_tests.c
  edhoc_integration_tests/initiator_responder_interaction.c
  edhoc_integration_tests/txrx_wrapper.c
  oscore_integration_tests/oscore_integration_tests.c
  oscore_latency_tests/oscore_latency_test.c
  oscore_unit_tests/unit_test_coap2oscore.c
  oscore_unit_tests/unit_test_option.c
  oscore_unit_tests/unit_test_oscore2coap.c
  oscore_unit_tests/unit_test_oscore_coap.c
  oscore_unit_tests/unit_test_oscore_interactions.c
  oscore_unit_tests/unit_test_replay_protection.c
  oscore_unit_tests/unit_test_security_context.c
  ../test_vectors/edhoc_test_vectors_rfc9529.c
  ../test_vectors/oscore_test_vectors.c
)

target_include_directories(app PRIVATE
  ${CMAKE_CURRENT_LIST_DIR}
  ${CMAKE_CURRENT_LIST_DIR}/../test_vectors
)

if(CONFIG_UOSCORE_UEDHOC_EXTERNAL_DEPS)
  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/uoscore_uedhoc_vendored_deps.cmake)
  uoscore_uedhoc_add_zephyr_vendored_deps(
    MBEDTLS_CONFIG_FILE ${CMAKE_CURRENT_LIST_DIR}/mbedtls_config_uoscore_uedhoc.h
  )
  # entropy.c provides the entropy source of the vendored Mbed TLS. It
  # includes the internal Mbed TLS header entropy_poll.h.
  target_sources(app PRIVATE entropy.c)
  target_include_directories(app PRIVATE ${UOSCORE_UEDHOC_EXTERNALS_DIR}/mbedtls/library)
  target_link_libraries(app PRIVATE uoscore_uedhoc_vendored_mbedtls)
endif()

# The test code's own debug prints follow the library's debug options, which
# are off by default. Enable both with overlay-debug.conf.
if(CONFIG_UOSCORE_DEBUG OR CONFIG_UEDHOC_DEBUG)
  target_compile_definitions(app PRIVATE DEBUG_PRINT)
endif()

target_compile_definitions(app PRIVATE
  #MEASURE_LATENCY_ON
  #REPORT_STACK_USAGE
)
