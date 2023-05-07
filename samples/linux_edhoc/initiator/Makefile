# Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
# file at the top-level directory of this distribution.

# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

# in order to rebuild the uoscore-uedhoc.a and initiator application call: 
# make oscore_edhoc; make

include ../../../makefile_config.mk
ROOT_DIR := ../../..
# toolchain
CXX ?= g++
CC ?= gcc
SZ ?= size
MAKE ?= make

# target
TARGET = initiator

# build path
BUILD_DIR = build

# libusocore-uedhoc path
USOCORE_UEDHOC_PATH = $(ROOT_DIR)
USOCORE_UEDHOC_BUILD_PATH = $(USOCORE_UEDHOC_PATH)/build

ifeq ($(ARCH_32_ONLY), 1)
# build for 32 bit x68 
# export the varible so that it is availbale in the uoscore-uedhoc Makefile 
ARCH = -m32
export ARCH
endif

# debug build?
DEBUG = 1

# optimization
OPT = -Og


# C defines
# make PRINT_ARRAY macro usable in the main file
C_DEFS += -DDEBUG_PRINT
C_DEFS += -DLINUX_SOCKETS

C_DEFS += $(ENV_DEFS)

# Linked libraries
LD_LIBRARY_PATH += -L$(USOCORE_UEDHOC_BUILD_PATH)

LDFLAGS += $(LD_LIBRARY_PATH)
LDFLAGS += -luoscore-uedhoc
LDFLAGS += -lstdc++
LDFLAGS += $(ARCH) 
##########################################
# CFLAGS
##########################################
#general c flags
CFLAGS +=  $(ARCH) $(C_DEFS) $(INCLUDES) $(OPT) -Wall
CXXFLAGS +=  $(ARCH) $(C_DEFS) $(INCLUDES) $(OPT)

# have dubug information
ifeq ($(DEBUG), 1)
CFLAGS += -g -gdwarf-2
CXXFLAGS += -Wall -g
endif

# Generate dependency information
CFLAGS += -MMD -MP -MF"$(@:%.o=%.d)"
CXXFLAGS += -MMD -MP -MF"$(@:%.o=%.d)" 
# required for gddl-gen library
CFLAGS += -DZCBOR_CANONICAL 

# use linux sockets 
CFLAGS += -DLINUX_SOCKETS
CXXFLAGS += -DLINUX_SOCKETS

# use AddressSanitizer to find memory bugs
# comment this out for better speed
#CFLAGS += -fsanitize=address -fno-omit-frame-pointer
#CXXFLAGS += -fsanitize=address -fno-omit-frame-pointer
#LDFLAGS += -fsanitize=address -static-libasan

USOCORE_UEDHOC_OBJ = $(wildcard $(USOCORE_UEDHOC_PATH)/*.o) 

INITIATOR_DIR := ${ROOT_DIR}/samples/linux_edhoc/initiator
INITIATOR_SOURCES := $(wildcard ${INITIATOR_DIR}/src/*.c) $(wildcard ${INITIATOR_DIR}/src/*.cpp)
INITIATOR_INCLUDES := -I${ROOT_DIR}/inc -I${ROOT_DIR}/test_vectors

COMMON_DIR := ${ROOT_DIR}/samples/common
COMMON_SOURCES := $(wildcard ${COMMON_DIR}/*.c)
COMMON_INCLUDES := -I$(COMMON_DIR)

ZCBOR_DIR := ${ROOT_DIR}/externals/zcbor
ZCBOR_C_SOURCES += $(wildcard ${ZCBOR_DIR}/src/*.c)
ZCBOR_INCLUDES := -I${ZCBOR_DIR}/include

MBEDTLS_DIR := ${ROOT_DIR}/externals/mbedtls
MBEDTLS_SOURCES := $(wildcard ${MBEDTLS_DIR}/library/*.c)
MBEDTLS_SRC_DIR := ${MBEDTLS_DIR}/library
MBEDTLS_INCLUDES := -I${MBEDTLS_DIR}/library -I${MBEDTLS_DIR}/include -I${MBEDTLS_DIR}/include/mbedtls -I${MBEDTLS_DIR}/include/psa

COMPACT25519_DIR := ${ROOT_DIR}/externals/compact25519/src
COMPACT25519_C_SOURCES :=  $(wildcard ${COMPACT25519_DIR}/c25519/*.c) $(wildcard ${COMPACT25519_DIR}/*.c)
COMPACT25519_INCLUDES := -I../../../externals/compact25519/src/c25519/ -I../../../externals/compact25519/src/ 

TINYCRYPT_ALL_C_SOURCES += $(wildcard ${TINYCRYPT_DIR}/*.c)
TINYCRYPT_INCLUDES := -I${ROOT_DIR}/externals/tinycrypt/lib/include
TINYCRYPT_SOURCES := $(filter-out ${TINYCRYPT_DIR}/sha256.c, $(wildcard ${ROOT_DIR}/externals/tinycrypt/lib/source/*.c))

CANTCOAP_DIR :=  ${ROOT_DIR}/externals/cantcoap
CANTCOAP_SOURCES := ${CANTCOAP_DIR}/cantcoap.cpp
CANTCOAP_INCLUDES := -I${CANTCOAP_DIR}

SOURCES := ${INITIATOR_SOURCES}
SOURCES += ${TINYCRYPT_SOURCES}
SOURCES += ${COMPACT25519_C_SOURCES}
SOURCES += ${MBEDTLS_SOURCES}
SOURCES += ${ZCBOR_C_SOURCES}
SOURCES += ${COMMON_SOURCES}
SOURCES += ${CANTCOAP_SOURCES}
OBJECTS := $(patsubst ${ROOT_DIR}/%.cpp,${BUILD_DIR}/%.o,$(patsubst ${ROOT_DIR}/%.c,${BUILD_DIR}/%.o,$(SOURCES)))
INCLUDES := ${TINYCRYPT_INCLUDES}
INCLUDES += ${COMPACT25519_INCLUDES}
INCLUDES += ${MBEDTLS_INCLUDES}
INCLUDES += ${ZCBOR_INCLUDES}
INCLUDES += ${COMMON_INCLUDES}
INCLUDES += ${INITIATOR_INCLUDES}
INCLUDES += ${CANTCOAP_INCLUDES}
###########################################
# default action: build all
###########################################

$(BUILD_DIR)/%.o: ${ROOT_DIR}/%.c | build_dirs
	$(CC) ${CFLAGS} ${INCLUDES} -Wa,-a,-ad,-alms=$(<:$(ROOT_DIR)/%.c=$(BUILD_DIR)/%.lst) -c $< -o $@

$(BUILD_DIR)/%.o: ${ROOT_DIR}/%.cpp | build_dirs
	$(CXX) ${CXXFLAGS} ${INCLUDES} -c $< -o $@
	
${BUILD_DIR}/${TARGET}:${OBJECTS} Makefile $(USOCORE_UEDHOC_PATH)/Makefile ${USOCORE_UEDHOC_OBJ}
	$(MAKE) -C $(USOCORE_UEDHOC_PATH)
	$(CXX) ${OBJECTS} ${LDFLAGS} -o $@
	$(SZ) $@

oscore_edhoc:
	$(MAKE) -C $(USOCORE_UEDHOC_PATH)

clean_oscore_edhoc:
	$(MAKE) -C $(USOCORE_UEDHOC_PATH) clean
	
build_dirs:
	mkdir -p $(sort $(dir ${OBJECTS}))

clean:
	-rm -fR $(BUILD_DIR)
	$(MAKE) -C $(USOCORE_UEDHOC_PATH) clean
#######################################
# dependencies
####################################### 
DEPENDENCIES := $(shell find ./$(BUILD_DIR) -name '*.d' -type f)
-include $(DEPENDENCIES)
