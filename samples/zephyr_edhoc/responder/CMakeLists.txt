# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.13.1)
set(ZEPHYR_EXTRA_MODULES 
	${CMAKE_CURRENT_SOURCE_DIR}/../../../modules/edhoc/
	${CMAKE_CURRENT_SOURCE_DIR}/../../../modules/c25519/)
include($ENV{ZEPHYR_BASE}/cmake/app/boilerplate.cmake NO_POLICY_SCOPE)
project(NONE)

FILE(GLOB app_sources src/*.c)
target_sources(app PRIVATE ${app_sources})
target_include_directories(app PRIVATE $ENV{ZEPHYR_BASE}/subsys/net/ip)


# external library OSOCRE
zephyr_include_directories( 
	src/
	${CMAKE_CURRENT_SOURCE_DIR}/../../../modules/edhoc/
	${CMAKE_CURRENT_SOURCE_DIR}/../../../modules/c25519/src
	#$ENV{ZEPHYR_BASE}/ext/lib/crypto/wolfssl/include
	
	#we use a specific version of tinycbor (0.5) with
	#git commit sha: 31ae89e4b768612722620cb6cb173a0de4a19cc9
	#zephyr2.2.9 has a new version of tinycbor (with still the same number 0.5?)
	#in order to use the correct version go to $ENV{ZEPHYR_BASE}/zephyr/west.yml
	# and set the tinycbor version to 31ae89e4b768612722620cb6cb173a0de4a19cc9
	# then run west update
	$ENV{ZEPHYR_BASE}/../modules/lib/tinycbor/src

)
add_definitions(
	-DEDHOC_DEBUG_PRINT
)

target_link_libraries(app PRIVATE edhoc TINYCBOR c25519)
