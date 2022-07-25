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
 * @brief Decodes an int from CBOR
 * 
 * @param in the input CBOR data
 * @param in_len the length of in
 * @param out result
 * @return enum err 
 */
enum err decode_int(uint8_t *in, uint32_t in_len, int32_t *out);

/**
 * @brief Encodes an int in CBOR
 * 
 * @param in the input int
 * @param in_len the length of the int
 * @param out the result
 * @param out_len length of out
 * @return enum err 
 */
enum err encode_int(const int32_t *in, uint32_t in_len, uint8_t *out,
		    uint32_t *out_len);
#endif