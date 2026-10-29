#!/bin/sh
#set -x #echo on

# run this script from the "test" directory after Zephyr is initialized with:
# cd <to test dir>
# ./ci_scripts/flash_report_gen.sh
# the script produces build_reports/flash_report.txt

echo "\n"
echo "*********************************************************************\n"
echo "start flash_report_gen.sh\n"
echo "*********************************************************************\n"
mkdir -p build_reports
rm -rf build_reports/rom_report_nrf91_with_tinycrypt.txt


# TINYCRYPT     YES
# MESSAGE_4:    YES
# VLA:          YES
rm -rf build
west build -b nrf9160dk/nrf9160 -- -DCONFIG_UEDHOC_MESSAGE_4=y -DCONFIG_UOSCORE_UEDHOC_TINYCRYPT=y -DEXTRA_CONF_FILE=overlay-external-deps.conf
west build -t rom_report > build_reports/rom_report_nrf91_with_tinycrypt.txt
echo "\n\n\n"

# MBEDTLS     YES
# MESSAGE_4:    YES
# VLA:          YES
rm -rf build
west build -b nrf9160dk/nrf9160 -- -DCONFIG_UEDHOC_MESSAGE_4=y
west build -t rom_report > build_reports/rom_report_nrf91_with_mbedtls.txt
