# SPDX-License-Identifier: Apache-2.0 OR MIT
#
#   cmake -S . -B build
#   cmake --build build
#   ./build/client

cmake_minimum_required(VERSION 3.28)
project(linux_oscore_client LANGUAGES C CXX)

include(${CMAKE_CURRENT_LIST_DIR}/../../linux_sample.cmake)

uoscore_uedhoc_linux_sample(client)
