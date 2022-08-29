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

enum err cose_enc_structure_encode(const uint8_t *context, uint32_t context_len,
				   const uint8_t *protected,
				   uint32_t protected_len,
				   const uint8_t *external_aad,
				   uint32_t external_aad_len, uint8_t *out,
				   uint32_t *out_len)
{
	struct edhoc_enc_structure enc_structure;

    enc_structure._edhoc_enc_structure_context.value = context;
    enc_structure._edhoc_enc_structure_context.len = context_len;
    enc_structure._edhoc_enc_structure_external_aad.value = external_aad;
	enc_structure._edhoc_enc_structure_external_aad.len = external_aad_len;

	/* NULL protected with zero size is acceptable from EDHOC point of view,
	 * but CBOR encoder does not accept NULL as input argument.
	 * Internally it calls memmove that generates runtime error when input
	 * is NULL even if length is set to 0.
	 * Workaround is to provide dummy buffer to avoid passing NULL. It does not
	 * impact the EDHOC process, since protected length is set to 0 and no value
	 * is copied to the EDHOC message. */
	const char dummy_buffer;

	if (NULL == protected) {
		if (0 != protected_len) {
			return wrong_parameter;
		}
		else {
			enc_structure._edhoc_enc_structure_protected.value = (const uint8_t *) &dummy_buffer;
		}
	}
	else {
		enc_structure._edhoc_enc_structure_protected.value = protected;
	}

	enc_structure._edhoc_enc_structure_protected.len = protected_len;

	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_edhoc_enc_structure(out, *out_len, &enc_structure,
					     &payload_len_out),
		   true);
	*out_len = (uint32_t) payload_len_out;
	return ok;
}

enum err cose_sig_structure_encode(const uint8_t *context, uint32_t context_len,
				   const uint8_t *protected,
				   uint32_t protected_len,
				   const uint8_t *external_aad,
				   uint32_t external_aad_len,
				   const uint8_t *payload, uint32_t payload_len,
				   uint8_t *out, uint32_t *out_len)
{
	struct sig_structure sig_structure;

	sig_structure._sig_structure_context.value = context;
	sig_structure._sig_structure_context.len = context_len;
	sig_structure._sig_structure_protected.value = protected;
	sig_structure._sig_structure_protected.len = protected_len;
	sig_structure._sig_structure_external_aad.value = external_aad;
	sig_structure._sig_structure_external_aad.len = external_aad_len;
	sig_structure._sig_structure_payload.value = payload;
	sig_structure._sig_structure_payload.len = payload_len;

	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_sig_structure(out, *out_len, &sig_structure,
					     &payload_len_out),
		   true);

	*out_len = (uint32_t) payload_len_out;
	return ok;
}
