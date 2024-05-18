/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#ifndef INT_ENCODE_DECODE_H
#define INT_ENCODE_DECODE_H

#include <stdint.h>
#include "common/oscore_edhoc_error.h"

/**
 * @brief 			Decodes an int from CBOR.
 * 
 * @param[in] in		The input CBOR data.
 * @param[out] out		The result.
 * @return 			Ok or error code. 
 */
enum err decode_int(const struct byte_array *in, int32_t *out);

/**
 * @brief 			Encodes an int in CBOR.
 * 
 * @param[in] in		The input int.
 * @param in_len 		The length of the int.
 * @param[out] out		The result.
 * @return 			Ok or error code. 
 */
enum err encode_int(const int32_t *in, uint32_t in_len, struct byte_array *out);

/**
 * @brief                       Checks if the C_I chosen by the user is actually 
 *                              an encoding for a CBOR int in the range -24..23 
 *                              or another byte string that needs to be encoded 
 *                              as CBOR bstr in message 1.
 * 
 * @param c_i                   Connection identifier of the initiator
 * @return true                 if it as int representation
 * @return false                if it is a raw byte string
 */
bool c_x_is_encoded_int(const struct byte_array *c_i);

/**
 * @brief                       Checks if C_R is raw int or a raw byte string
 * 
 * @param c_r                   Connection identifier of the responder
 * @return true                 if it is a raw int
 * @return false                if it is a raw byte string
 */
bool c_r_is_raw_int(const struct byte_array *c_r);

#endif