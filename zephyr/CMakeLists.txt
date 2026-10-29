# Copyright (c) 2022 Nordic Semiconductor ASA
# SPDX-License-Identifier: Apache-2.0
#
# Zephyr module build of uoscore-uedhoc. Moved from the Zephyr tree
# (modules/uoscore-uedhoc/CMakeLists.txt). The source files come from
# cmake/uoscore_uedhoc_sources.cmake, which the standalone build uses too.

if(CONFIG_UOSCORE OR CONFIG_UEDHOC)

  include(${CMAKE_CURRENT_LIST_DIR}/../cmake/uoscore_uedhoc_sources.cmake)

  zephyr_include_directories(${UOSCORE_UEDHOC_INCLUDE_DIR})

  # These macros change headers in inc/. zephyr_compile_definitions() applies
  # them to the application too, so both compile the headers the same way.
  # zephyr_library_compile_definitions() would apply them to the library only.
  zephyr_compile_definitions_ifdef(CONFIG_UOSCORE_NVM_SUPPORT OSCORE_NVM_SUPPORT)
  zephyr_compile_definitions_ifdef(CONFIG_UOSCORE_UEDHOC_VLA VLA)
  zephyr_compile_definitions_ifdef(CONFIG_UOSCORE_UEDHOC_UNIT_TEST UNIT_TEST)

  # Macros used only by the library's .c files.
  set(UOSCORE_UEDHOC_PRIVATE_DEFINITIONS MBEDTLS)
  if(CONFIG_UOSCORE_UEDHOC_TINYCRYPT)
    list(APPEND UOSCORE_UEDHOC_PRIVATE_DEFINITIONS TINYCRYPT)
  endif()
  if(CONFIG_UOSCORE_UEDHOC_COMPACT25519)
    list(APPEND UOSCORE_UEDHOC_PRIVATE_DEFINITIONS COMPACT25519)
  endif()

  if(CONFIG_UOSCORE_UEDHOC_EXTERNAL_DEPS AND NOT UOSCORE_UEDHOC_DEPENDENCY_TARGETS)
    message(FATAL_ERROR
      "CONFIG_UOSCORE_UEDHOC_EXTERNAL_DEPS=y: set UOSCORE_UEDHOC_DEPENDENCY_TARGETS "
      "to the dependency targets before find_package(Zephyr)")
  endif()

  # Creates one Zephyr library with the settings shared by all three.
  # The dependency targets are created by the application after this file
  # runs, so they cannot be checked here. LINK_LIBRARIES_ONLY_TARGETS makes
  # CMake check them at generate time: a misspelled name stops the configure
  # step with a clear error instead of a late "cannot find -l<name>" from the
  # linker.
  macro(uoscore_uedhoc_zephyr_library name)
    zephyr_library_named(${name})
    zephyr_library_sources(${ARGN})
    zephyr_library_compile_definitions(${UOSCORE_UEDHOC_PRIVATE_DEFINITIONS})
    if(CONFIG_UOSCORE_UEDHOC_EXTERNAL_DEPS)
      zephyr_library_link_libraries(${UOSCORE_UEDHOC_DEPENDENCY_TARGETS})
      set_target_properties(${name} PROPERTIES LINK_LIBRARIES_ONLY_TARGETS ON)
    else()
      zephyr_library_link_libraries_ifdef(CONFIG_MBEDTLS_BUILTIN mbedtls_iface)
      zephyr_library_link_libraries_ifdef(CONFIG_UOSCORE_UEDHOC_COMPACT25519
        uoscore_uedhoc_compact25519)
    endif()
  endmacro()

# compact25519 from externals/ (not a Zephyr module)

  if(CONFIG_UOSCORE_UEDHOC_COMPACT25519 AND NOT CONFIG_UOSCORE_UEDHOC_EXTERNAL_DEPS)
    include(${CMAKE_CURRENT_LIST_DIR}/../cmake/uoscore_uedhoc_vendored_deps.cmake)
    if(NOT EXISTS ${UOSCORE_UEDHOC_EXTERNALS_DIR}/compact25519/src/compact_x25519.c)
      message(FATAL_ERROR
        "CONFIG_UOSCORE_UEDHOC_COMPACT25519=y needs the externals/compact25519 "
        "git submodule: git -C ${UOSCORE_UEDHOC_EXTERNALS_DIR}/.. submodule "
        "update --init externals/compact25519")
    endif()
    zephyr_library_named(uoscore_uedhoc_compact25519)
    zephyr_library_sources(${UOSCORE_UEDHOC_COMPACT25519_SOURCES})
    target_include_directories(uoscore_uedhoc_compact25519 SYSTEM PUBLIC
      ${UOSCORE_UEDHOC_COMPACT25519_INCLUDE_DIRS})
  endif()

# Common part used by both libraries

  uoscore_uedhoc_zephyr_library(uoscore_uedhoc_common ${UOSCORE_UEDHOC_COMMON_SOURCES})

  if(CONFIG_UOSCORE_DEBUG OR CONFIG_UEDHOC_DEBUG)
    zephyr_library_compile_definitions(DEBUG_PRINT)
  endif()

  if(CONFIG_BUILD_WITH_TFM)
    zephyr_library_include_directories(
      $<TARGET_PROPERTY:tfm,TFM_BINARY_DIR>/api_ns/interface/include
    )
  endif()

# UOSCORE

  if(CONFIG_UOSCORE)
    uoscore_uedhoc_zephyr_library(uoscore ${UOSCORE_SOURCES})
    zephyr_library_compile_definitions_ifdef(CONFIG_UOSCORE_DEBUG DEBUG_PRINT)
    if(CONFIG_UOSCORE_NVM_SUPPORT AND NOT CONFIG_UOSCORE_NVM_CUSTOM)
      zephyr_library_sources(${CMAKE_CURRENT_LIST_DIR}/uoscore_nvm.c)
    endif()
  endif()

# UEDHOC

  if(CONFIG_UEDHOC)
    uoscore_uedhoc_zephyr_library(uedhoc ${UEDHOC_SOURCES})
    zephyr_library_compile_definitions_ifdef(CONFIG_UEDHOC_DEBUG DEBUG_PRINT)
    zephyr_library_compile_definitions_ifdef(CONFIG_UEDHOC_MESSAGE_4 MESSAGE_4)
  endif()

endif() # CONFIG_UOSCORE OR CONFIG_UEDHOC
