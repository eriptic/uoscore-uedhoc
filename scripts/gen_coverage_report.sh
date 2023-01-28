#!/bin/sh

# Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
# file at the top-level directory of this distribution.

# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

# This script generates a code coverage report.
# For more information see: https://docs.zephyrproject.org/latest/develop/test/coverage.html#coverage-reports-using-the-posix-architecture

cd ../test
rm -rf build/
rm -rf ../build/
rm -rf ../report_coverage/
rm lcov.info
west build -b native_posix -- -DCONFIG_COVERAGE=y
west build -t run
lcov --capture --directory ./ --output-file lcov.info -q --rc lcov_branch_coverage=1
genhtml lcov.info --output-directory ../report_coverage -q --ignore-errors source --branch-coverage --highlight --legend