/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdint.h>

#include "edhoc/edhoc_cose.h"

#include "common/oscore_edhoc_error.h"

#include "cbor/edhoc_encode_enc_structure.h"
#include "cbor/edhoc_encode_sig_structure.h"

enum err cose_enc_structure_encode(const struct byte_array *context,
				   const struct byte_array *protected,
				   const struct byte_array *external_aad,
				   struct byte_array *out)
{
	struct edhoc_enc_structure enc_structure;

	enc_structure.edhoc_enc_structure_context.value = context->ptr;
	enc_structure.edhoc_enc_structure_context.len = context->len;
	enc_structure.edhoc_enc_structure_external_aad.value =
		external_aad->ptr;
	enc_structure.edhoc_enc_structure_external_aad.len = external_aad->len;

	/* NULL protected with zero size is acceptable from EDHOC point of view,
	 * but CBOR encoder does not accept NULL as input argument.
	 * Internally it calls memmove that generates runtime error when input
	 * is NULL even if length is set to 0.
	 * Workaround is to provide dummy buffer to avoid passing NULL. It does not
	 * impact the EDHOC process, since protected length is set to 0 and no value
	 * is copied to the EDHOC message. */
	const char dummy_buffer;

	if (NULL == protected->ptr) {
		if (0 != protected->len) {
			return wrong_parameter;
		} else {
			enc_structure.edhoc_enc_structure_protected.value =
				(const uint8_t *)&dummy_buffer;
		}
	} else {
		enc_structure.edhoc_enc_structure_protected.value =
			protected->ptr;
	}

	enc_structure.edhoc_enc_structure_protected.len = protected->len;

	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_edhoc_enc_structure(out->ptr, out->len,
						   &enc_structure,
						   &payload_len_out),
		   0);
	out->len = (uint32_t)payload_len_out;
	return ok;
}

enum err cose_sig_structure_encode(const struct byte_array *context,
				   const struct byte_array *protected,
				   const struct byte_array *external_aad,
				   const struct byte_array *payload,
				   struct byte_array *out)
{
	struct sig_structure sig_structure;

	sig_structure.sig_structure_context.value = context->ptr;
	sig_structure.sig_structure_context.len = context->len;
	sig_structure.sig_structure_protected.value = protected->ptr;
	sig_structure.sig_structure_protected.len = protected->len;
	sig_structure.sig_structure_external_aad.value = external_aad->ptr;
	sig_structure.sig_structure_external_aad.len = external_aad->len;
	sig_structure.sig_structure_payload.value = payload->ptr;
	sig_structure.sig_structure_payload.len = payload->len;

	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_sig_structure(out->ptr, out->len, &sig_structure,
					     &payload_len_out),
		   0);

	out->len = (uint32_t)payload_len_out;
	return ok;
}
