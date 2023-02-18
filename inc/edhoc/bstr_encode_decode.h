/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#ifndef BSTR_ENCODE_DECODE_H
#define BSTR_ENCODE_DECODE_H

#include <stdint.h>
/**
 * @brief                       Encodes an array of data to cbor byte string.
 * 
 * @param[in] in                Data to be encoded.
 * @param[out] out              The output buffer.
 * @retval                      Ok or error code.
 */
enum err encode_bstr(const struct byte_array *in, struct byte_array *out);

/**
 * @brief                       Decodes an a cbor bstr to an array of data.
 * 
 * @param[in] in                Cbor bstr.
 * @param[out] out              Ouput buffer.
 * @return                      Ok or error code.
 */
enum err decode_bstr(const struct byte_array *in, struct byte_array *out);

#endif