/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include "common/oscore_edhoc_error.h"
#include "common/byte_array.h"

#include "cbor/edhoc_encode_int_type.h"
#include "cbor/edhoc_decode_int_type.h"

enum err encode_int(const int32_t *in, uint32_t in_len, struct byte_array *out)
{
	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_int_type_i(out->ptr, out->len, in,
					  &payload_len_out),
		   0);
	out->len = (uint32_t)payload_len_out;
	return ok;
}

enum err decode_int(const struct byte_array *in, int32_t *out)
{
	size_t decode_len = 0;
	TRY_EXPECT(cbor_decode_int_type_i(in->ptr, in->len, out, &decode_len),
		   0);
	if (decode_len != 1) {
		return cbor_decoding_error;
	}
	return ok;
}