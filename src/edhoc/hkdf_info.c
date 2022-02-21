/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <string.h>

#include "edhoc/suites.h"
#include "edhoc/hkdf_info.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

#include "cbor/edhoc_encode_info.h"

enum err create_hkdf_info(const uint8_t *th, uint32_t th_len, const char *label,
			  uint8_t *context, uint32_t context_len,
			  uint32_t okm_len, uint8_t *out, uint32_t *out_len)
{
	struct info info;

	info._info_transcript_hash.value = th;
	info._info_transcript_hash.len = th_len;

	info._info_label.value = (const uint8_t *)label;
	info._info_label.len = (uint32_t)strlen(label);

	info._info_context.value = context;
	info._info_context.len = context_len;

	info._info_length = okm_len;

	size_t payload_len_out = 0;
	TRY_EXPECT(cbor_encode_info(out, *out_len, &info, &payload_len_out),
		   true);

	*out_len = (uint32_t) payload_len_out;

	return ok;
}
