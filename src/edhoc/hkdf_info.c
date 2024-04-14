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

enum err create_hkdf_info(uint8_t label, struct byte_array *context,
			  uint32_t okm_len, struct byte_array *out)
{
	struct info info;

	info.info_label = label;

	/* NULL context with zero size is acceptable from EDHOC point of view,
	 * but CBOR encoder does not accept NULL as input argument.
	 * Internally it calls memmove that generates runtime error when input
	 * is NULL even if length is set to 0.
	 * Workaround is to provide dummy buffer to avoid passing NULL. It does not
	 * impact the EDHOC process, since context length is set to 0 and no value
	 * is copied to the EDHOC message. */
	const char dummy_buffer;

	if (NULL == context->ptr) {
		if (0 != context->len) {
			return wrong_parameter;
		} else {
			info.info_context.value =
				(const uint8_t *)&dummy_buffer;
		}
	} else {
		info.info_context.value = context->ptr;
	}

	info.info_context.len = context->len;

	info.info_length = okm_len;

	size_t payload_len_out = 0;
	TRY_EXPECT(cbor_encode_info(out->ptr, out->len, &info,
				    &payload_len_out),
		   0);

	out->len = (uint32_t)payload_len_out;

	return ok;
}
