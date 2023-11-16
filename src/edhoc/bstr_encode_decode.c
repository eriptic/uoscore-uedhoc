/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include "zcbor_common.h"
#include "cbor/edhoc_encode_bstr_type.h"
#include "cbor/edhoc_decode_bstr_type.h"

#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"
#include "common/byte_array.h"

enum err encode_bstr(const struct byte_array *in, struct byte_array *out)
{
	size_t payload_len_out;
	struct zcbor_string tmp;
	tmp.value = in->ptr;
	tmp.len = in->len;
	TRY_EXPECT(cbor_encode_bstr_type_b_str(out->ptr, out->len, &tmp,
					       &payload_len_out),
		   0);
	out->len = (uint32_t)payload_len_out;
	return ok;
}

enum err decode_bstr(const struct byte_array *in, struct byte_array *out)
{
	struct zcbor_string str;
	size_t decode_len = 0;

	TRY_EXPECT(cbor_decode_bstr_type_b_str(in->ptr, in->len, &str,
					       &decode_len),
		   0);

	TRY(_memcpy_s(out->ptr, out->len, str.value, (uint32_t)str.len));
	out->len = (uint32_t)str.len;

	return ok;
}
