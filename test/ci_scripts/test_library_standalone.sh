#!/bin/bash

# Checks the standalone CMake build of the library (the top-level
# CMakeLists.txt, which the Zephyr tests do not use):
#   - every .c file in src/ is in cmake/uoscore_uedhoc_sources.cmake
#   - the library builds with warnings as errors
#   - the API headers edhoc.h and oscore.h are self-contained

set -e

SCRIPT_DIR="$( cd -- "$( dirname -- "${BASH_SOURCE[0]}" )" &> /dev/null && pwd )"
cd "$SCRIPT_DIR/../.."

cmake -P cmake/check_source_list.cmake
cmake --workflow --preset ci --fresh
