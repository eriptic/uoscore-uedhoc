/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include "common/oscore_edhoc_error.h"
#include "common/byte_array.h"

#include "cbor/edhoc_encode_int_type.h"
#include "cbor/edhoc_decode_int_type.h"

bool c_x_is_encoded_int(const struct byte_array *c_i)
{
	if (c_i->len == 1 && ((0x00 <= c_i->ptr[0] && c_i->ptr[0] < 0x18) ||
			      (0x1F < c_i->ptr[0] && c_i->ptr[0] <= 0x37))) {
		return true;
	} else {
		return false;
	}
}

enum err encode_int(int32_t *in, uint32_t in_len, struct byte_array *out)
{
	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_int_type_i(out->ptr, out->len, in,
					  &payload_len_out),
		   0);
	out->len = (uint32_t)payload_len_out;
	return ok;
}

enum err c_x_int_encode(int32_t in, struct byte_array *out)
{
	if (in < -24 || in > 23) {
		return cbor_decoding_error;
	}
	TRY(encode_int(&in, 1, out));
	if (!c_x_is_encoded_int(out)) {
		return cbor_encoding_error;
	}
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
