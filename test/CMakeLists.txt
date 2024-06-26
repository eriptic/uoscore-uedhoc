# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)
find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})

project(auto_test)

if(COMMAND_LINE_FLAGS MATCHES "ASAN")
target_compile_options(app PRIVATE -fsanitize=address -fomit-frame-pointer)
endif()

FILE(GLOB app_sources
  *.c
  edhoc_integration_tests/*.c
  oscore_integration_tests/*.c
  oscore_unit_tests/*.c
  oscore_latency_tests/*.c
  mocks/*.c
  ../externals/zcbor/src/*.c
  ../externals/compact25519/src/c25519/*.c
  ../externals/compact25519/src/*.c
  ../externals/mbedtls/library/*.c
  ../externals/tinycrypt/lib/source/*.c
  ../test_vectors/*.c)
target_sources(app PRIVATE ${app_sources})

include_directories(
  .
  ../inc
  ../test_vectors
  ../externals/zcbor/include
  ../externals/mbedtls/library
  ../externals/mbedtls/include
  ../externals/mbedtls/include/mbedtls
  ../externals/mbedtls/include/psa
  ../externals/tinycrypt/lib/include)

add_definitions(
  -DMBEDTLS_CONFIG_FILE="mbedtls_config_uoscore_uedhoc.h"
  -DUNIT_TEST
  -DDEBUG_PRINT
  -DZCBOR_CANONICAL
  #-DMEASURE_LATENCY_ON
  #-DREPORT_STACK_USAGE
)

# The external static library that we are linking with does not know
# how to build for this platform so we export all the flags used in
# this zephyr build to the external build system.
zephyr_get_include_directories_for_lang_as_string(C includes)
zephyr_get_system_include_directories_for_lang_as_string(C system_includes)
zephyr_get_compile_definitions_for_lang_as_string(C definitions)
zephyr_get_compile_options_for_lang_as_string(C options)

#message("C includes is: ${includes}")
#message("C system_includes is: ${system_includes}")
#message("C definitions is: ${definitions}")
#message("C options is: ${options}")

# To provide flags with west use COMMAND_LINE_FLAGS, e.g.:
# west build -b native_posix -- -DCOMMAND_LINE_FLAGS="-DVLA"
set(external_project_cflags
  "${COMMAND_LINE_FLAGS} ${includes} ${definitions} ${options} ${system_includes}"
)

include(ExternalProject)

# Add an external project to be able download and build the third
# party library. In this case downloading is not necessary as it has
# been committed to the repository.
set(src_dir ${CMAKE_CURRENT_SOURCE_DIR}/..)
set(build_dir ${CMAKE_CURRENT_BINARY_DIR}/uoscore_uedhoc)

set(LIB_TEST_LIB_DIR ${CMAKE_CURRENT_SOURCE_DIR}/../build)
set(INCLUDE_DIR ${CMAKE_CURRENT_SOURCE_DIR}/..)

if(CMAKE_GENERATOR STREQUAL "Unix Makefiles")
  # https://www.gnu.org/software/make/manual/html_node/MAKE-Variable.html
  set(submake "$(MAKE)")
else() # Obviously no MAKEFLAGS. Let's hope a "make" can be found somewhere.
  set(submake "make")
endif()

message("build_dir: ${build_dir}")
message("CMAKE_CURRENT_SOURCE_DIR: ${CMAKE_CURRENT_SOURCE_DIR}")
message("CMAKE_CURRENT_BINARY_DIR: ${CMAKE_CURRENT_BINARY_DIR}")
message("LIB_TEST_LIB_DIR: ${LIB_TEST_LIB_DIR}")
message("INCLUDE_DIR: ${INCLUDE_DIR}")

ExternalProject_Add(
  oscore_edhoc_project # Name for custom target
  PREFIX ${build_dir} # Root dir for entire project
  SOURCE_DIR ${src_dir}
  BINARY_DIR ${src_dir} # This particular build system is invoked from the root
  CONFIGURE_COMMAND "" # Skip configuring the project, e.g. with autoconf
  BUILD_COMMAND
  ${submake}
  PREFIX=${build_dir}
  CC=${CMAKE_C_COMPILER}
  AR=${CMAKE_AR}
  CFLAGS=${external_project_cflags}
  INSTALL_COMMAND "" # This particular build system has no install command
  BUILD_BYPRODUCTS ${build_dir}/libuoscore-uedhoc.a
)

# Create a wrapper CMake library that our app can link with
add_library(test STATIC IMPORTED GLOBAL)
add_dependencies(
  test
  oscore_edhoc_project
)
set_target_properties(test PROPERTIES IMPORTED_LOCATION ${build_dir}/libuoscore-uedhoc.a)
target_include_directories(test INTERFACE
  ${INCLUDE_DIR}
)

target_link_libraries(app PRIVATE test)
