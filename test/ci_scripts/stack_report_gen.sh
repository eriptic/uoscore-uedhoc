#!/bin/sh

# run this script from the "test" directory after Zephyr is initialized with:
# cd <to test dir>
# ./ci_scripts/stack_report_gen.sh
# the script produces build_reports/stack_report.html

mkdir -p build_reports
rm -rf build_reports/stack_report.html


# TINYCRYPT     YES
# MESSAGE_4:    YES
# VLA:          YES
rm -rf build
west build -b native_sim/native/64 -- -DCONFIG_UOSCORE_UEDHOC_VLA=y -DCONFIG_UEDHOC_MESSAGE_4=y -DCONFIG_UOSCORE_UEDHOC_TINYCRYPT=y -DEXTRA_CONF_FILE=overlay-external-deps.conf
gdb --batch -ex 'py arg_flags="-DVLA -DMESSAGE_4 -DTINYCRYPT"' -x ci_scripts/stack_watch.py


# MBEDTLS     YES
# MESSAGE_4:    YES
# VLA:          YES
rm -rf build
west build -b native_sim/native/64 -- -DCONFIG_UOSCORE_UEDHOC_VLA=y -DCONFIG_UEDHOC_MESSAGE_4=y
gdb --batch -ex 'py arg_flags="-DVLA -DMESSAGE_4 -DMBEDTLS"' -x ci_scripts/stack_watch.py


# TINYCRYPT     YES
# MESSAGE_4:    YES
# VLA:          NO
rm -rf build
west build -b native_sim/native/64 -- -DCONFIG_UEDHOC_MESSAGE_4=y -DCONFIG_UOSCORE_UEDHOC_TINYCRYPT=y -DEXTRA_CONF_FILE=overlay-external-deps.conf
gdb --batch -ex 'py arg_flags="-DMESSAGE_4 -DTINYCRYPT"' -x ci_scripts/stack_watch.py

# MBEDTLS     YES
# MESSAGE_4:    YES
# VLA:          NO
rm -rf build
west build -b native_sim/native/64 -- -DCONFIG_UEDHOC_MESSAGE_4=y
gdb --batch -ex 'py arg_flags="-DMESSAGE_4 -DMBEDTLS"' -x ci_scripts/stack_watch.py
