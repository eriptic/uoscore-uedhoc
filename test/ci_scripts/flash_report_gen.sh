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
west build -b nrf9160dk_nrf9160 -- -DCOMMAND_LINE_FLAGS="-DMESSAGE_4 -DTINYCRYPT"
west build -t rom_report > build_reports/rom_report_nrf91_with_tinycrypt.txt
echo "\n\n\n"

# MBEDTLS     YES
# MESSAGE_4:    YES
# VLA:          YES
rm -rf build
west build -b nrf9160dk_nrf9160 -- -DCOMMAND_LINE_FLAGS="-DMESSAGE_4 -DMBEDTLS"
west build -t rom_report > build_reports/rom_report_nrf91_with_mbedtls.txt