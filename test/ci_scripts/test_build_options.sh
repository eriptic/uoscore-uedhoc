#!/bin/sh

# run this script in an initialized zephyr environment


# SANITIZER:    YES
# MESSAGE_4:    YES
# VLA:          YES
rm -rf build
west build -b native_posix -- -DCOMMAND_LINE_FLAGS="-DVLA -DASAN -DMESSAGE_4" -DCONFIG_ASAN=y
west build -t run

# SANITIZER:    YES
# MESSAGE_4:    No
# VLA:          YES
rm -rf build
west build -b native_posix -- -DCOMMAND_LINE_FLAGS="-DVLA -DASAN " -DCONFIG_ASAN=y
west build -t run

# SANITIZER:    YES
# MESSAGE_4:    YES
# VLA:          No
rm -rf build
west build -b native_posix -- -DCOMMAND_LINE_FLAGS="-DASAN -DMESSAGE_4" -DCONFIG_ASAN=y
west build -t run

# SANITIZER:    YES
# MESSAGE_4:    No
# VLA:          No
rm -rf build
west build -b native_posix -- -DCOMMAND_LINE_FLAGS="-DASAN " -DCONFIG_ASAN=y
west build -t run