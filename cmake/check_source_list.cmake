# SPDX-License-Identifier: Apache-2.0 OR MIT

# Fails if a .c file under src/ is missing from cmake/uoscore_uedhoc_sources.cmake,
# or if the list names a file that does not exist.
#
# Usage (from any directory):
#   cmake -P cmake/check_source_list.cmake

cmake_minimum_required(VERSION 3.28)

include(${CMAKE_CURRENT_LIST_DIR}/uoscore_uedhoc_sources.cmake)

set(listed ${UOSCORE_UEDHOC_COMMON_SOURCES} ${UOSCORE_SOURCES} ${UEDHOC_SOURCES})
file(GLOB_RECURSE on_disk "${UOSCORE_UEDHOC_ROOT}/src/*.c")

set(errors "")
foreach(file IN LISTS on_disk)
  if(NOT file IN_LIST listed)
    string(APPEND errors "  not listed: ${file}\n")
  endif()
endforeach()
foreach(file IN LISTS listed)
  if(NOT EXISTS "${file}")
    string(APPEND errors "  listed but missing: ${file}\n")
  endif()
endforeach()

if(errors)
  message(FATAL_ERROR
    "cmake/uoscore_uedhoc_sources.cmake is out of date:\n${errors}")
endif()

list(LENGTH listed count)
message(STATUS "Source list OK (${count} files)")
