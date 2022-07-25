/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#ifndef BSTR_ENCODE_DECODE_H
#define BSTR_ENCODE_DECODE_H

#include <stdint.h>
/**
 * @brief   Encodes an array of data to cbor byte string
 * 
 * @param   in Pointer to data to be encoded
 * @param   in_len Length of in
 * @param   out Pointer to the output buffer
 * @param   out_len Length of out
 * @retval   enum err An error code in a case of an error, else 0
 */
enum err encode_byte_string(const uint8_t *in, uint32_t in_len, uint8_t *out,
			    uint32_t *out_len);

/**
 * @brief Decodes an a cbor bstr to an array of data
 * 
 * @param in Pointer to a cbor bstr
 * @param in_len Length of in
 * @param out Pointer to the ouput buffer
 * @param out_len Length of out
 * @return enum err An error code in a case of an error, else 0
 */
enum err decode_byte_string(const uint8_t *in, const uint32_t in_len,
			    uint8_t *out, uint32_t *out_len);

#endif