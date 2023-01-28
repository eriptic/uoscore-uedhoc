#!/bin/bash




cd ..
make clean
make
rm -rf report_stack_usage/
mkdir report_stack_usage/
cd scripts
./avstack.pl ../build/*.o > ../report_stack_usage/report.txt