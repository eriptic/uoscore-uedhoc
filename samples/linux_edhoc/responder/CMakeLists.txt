# SPDX-License-Identifier: Apache-2.0 OR MIT
#
#   cmake -S . -B build
#   cmake --build build
#   ./build/responder

cmake_minimum_required(VERSION 3.28)
project(linux_edhoc_responder LANGUAGES C CXX)

include(${CMAKE_CURRENT_LIST_DIR}/../../linux_sample.cmake)

uoscore_uedhoc_linux_sample(responder)
