#!/bin/sh

# Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
# file at the top-level directory of this distribution.

# Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
# http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
# <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
# option. This file may not be copied, modified, or distributed
# except according to those terms.

# This script converts the cddl models into c source and header files

ZCBOR="../externals/zcbor/zcbor/zcbor.py"
MODELS_PATH="../cddl_models"
SRC="../src/cbor"
INC="../inc/cbor"
INC_PATH_IN_C_FILES="cbor/"


#clean up 
echo clean up...
rm $INC/*.h
rm $SRC/*.c

echo Generating CBOR encoding and decoding functions...  

#
# OSCORE
#

python3 $ZCBOR code -c $MODELS_PATH/oscore_aad_array.cddl -e -t aad_array  --oc $SRC/oscore_aad_array.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/oscore_aad_array.h

python3 $ZCBOR code -c $MODELS_PATH/oscore_info.cddl -e -t oscore_info --oc $SRC/oscore_info.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/oscore_info.h

python3 $ZCBOR code -c $MODELS_PATH/oscore_enc_structure.cddl -e -t oscore_enc_structure --oc $SRC/oscore_enc_structure.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/oscore_enc_structure.h

#
# EDHOC
#

#encode message 1
python3 $ZCBOR code -c $MODELS_PATH/edhoc_message_1.cddl -e -t message_1 --oc $SRC/edhoc_encode_message_1.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_message_1.h
#decode message 1
python3 $ZCBOR code -c $MODELS_PATH/edhoc_message_1.cddl -d -t message_1 --oc $SRC/edhoc_decode_message_1.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_decode_message_1.h

#encode message 2
python3 $ZCBOR code -c $MODELS_PATH/edhoc_message_2.cddl -e -t m2 --oc $SRC/edhoc_encode_message_2.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_message_2.h
#decode message 2
python3 $ZCBOR code -c $MODELS_PATH/edhoc_message_2.cddl -d -t m2 --oc $SRC/edhoc_decode_message_2.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_decode_message_2.h

#encode message 3
python3 $ZCBOR code -c $MODELS_PATH/edhoc_message_3.cddl -e -t m3 --oc $SRC/edhoc_encode_message_3.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_message_3.h

#decode message 3
python3 $ZCBOR code -c $MODELS_PATH/edhoc_message_3.cddl -d -t m3 --oc $SRC/edhoc_decode_message_3.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_decode_message_3.h

# encode error message
python3 $ZCBOR code -c $MODELS_PATH/edhoc_message_error.cddl -e -t message_error --oc $SRC/edhoc_encode_message_error.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_message_error.h


# ###   cose   ###

python3 $ZCBOR code -c $MODELS_PATH/edhoc_cose.cddl -e -t edhoc_enc_structure --oc $SRC/edhoc_encode_enc_structure.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_enc_structure.h

python3 $ZCBOR code -c $MODELS_PATH/edhoc_cose.cddl -e -t sig_structure --oc $SRC/edhoc_encode_sig_structure.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_sig_structure.h



###   other  ###

# encode data_2 
python3 $ZCBOR code -c $MODELS_PATH/edhoc_data_2.cddl -e -t data_2 --oc $SRC/edhoc_encode_data_2.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_data_2.h

# info
python3 $ZCBOR code -c $MODELS_PATH/edhoc_info.cddl -e -t info --oc $SRC/edhoc_encode_info.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_info.h

# plaintext
python3 $ZCBOR code -c $MODELS_PATH/edhoc_plaintext.cddl -d -t plaintext --oc $SRC/edhoc_decode_plaintext.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_decode_plaintext.h

# encode ID_CRED_x
python3 $ZCBOR code -c $MODELS_PATH/edhoc_plaintext.cddl -e -t id_cred_x_map --oc $SRC/edhoc_encode_id_cred_x.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_id_cred_x.h

# decode ID_CRED_x
python3 $ZCBOR code -c $MODELS_PATH/edhoc_plaintext.cddl -d -t id_cred_x_map --oc $SRC/edhoc_decode_id_cred_x.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_decode_id_cred_x.h

# decode Native CBOR certificate
python3 $ZCBOR code -c $MODELS_PATH/edhoc_cert.cddl -d -t cert --oc $SRC/edhoc_decode_cert.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_decode_cert.h

# encode th2
python3 $ZCBOR code -c $MODELS_PATH/edhoc_th.cddl -e -t th2 --oc $SRC/edhoc_encode_th2.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_th2.h

### primitive types ###
#encode byte_string
python3 $ZCBOR code -c $MODELS_PATH/edhoc_primitive_types.cddl -e -t bstr_type --oc $SRC/edhoc_encode_bstr_type.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_bstr_type.h

#decode byte_string
python3 $ZCBOR code -c $MODELS_PATH/edhoc_primitive_types.cddl -d -t bstr_type --oc $SRC/edhoc_decode_bstr_type.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_decode_bstr_type.h

#encode int
python3 $ZCBOR code -c $MODELS_PATH/edhoc_primitive_types.cddl -e -t int_type --oc $SRC/edhoc_encode_int_type.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_encode_int_type.h


#decode int
python3 $ZCBOR code -c $MODELS_PATH/edhoc_primitive_types.cddl -d -t int_type --oc $SRC/edhoc_decode_int_type.c --include-prefix $INC_PATH_IN_C_FILES --oh $INC/edhoc_decode_int_type.h