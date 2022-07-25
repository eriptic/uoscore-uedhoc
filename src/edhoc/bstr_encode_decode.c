/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include "cbor/edhoc_encode_bstr_type.h"
#include "cbor/edhoc_decode_bstr_type.h"

#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"

enum err encode_byte_string(const uint8_t *in, uint32_t in_len, uint8_t *out,
			    uint32_t *out_len)
{
	size_t payload_len_out;
	struct zcbor_string tmp;
	tmp.value = in;
	tmp.len = in_len;
	TRY_EXPECT(cbor_encode_bstr_type_b_str(out, *out_len, &tmp,
					       &payload_len_out),
		   true);
	*out_len = (uint32_t)payload_len_out;
	return ok;
}

enum err decode_byte_string(const uint8_t *in, const uint32_t in_len,
			    uint8_t *out, uint32_t *out_len)
{
	struct zcbor_string str;
	size_t decode_len = 0;

	TRY_EXPECT(cbor_decode_bstr_type_b_str(in, in_len, &str, &decode_len),
		   true);

	TRY(_memcpy_s(out, *out_len, str.value, (uint32_t)str.len));
	*out_len = (uint32_t)str.len;

	return ok;
}