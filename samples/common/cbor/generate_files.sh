#!/bin/sh

# Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
# file at the top-level directory of this distribution.

# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

echo Generating CBOR encoding and decoding functions...  

rm *.h
rm *.c


#decode C_I or C_R 
python3 ../../../externals/cddl-gen/zcbor/zcbor.py -c c_x.cddl code -d -t cx --oc decode_c_x.c --oh decode_c_x.h

#decode SUITES_I 
python3 ../../../externals/cddl-gen/zcbor/zcbor.py -c suites_i.cddl code -d -t suites --oc decode_suites_i.c --oh decode_suites_i.h