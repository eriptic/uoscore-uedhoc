/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "oscore.h"

#include "oscore/aad.h"
#include "oscore/option.h"

#include "common/print_util.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"

#include "cbor/oscore_aad_array.h"

enum err create_aad(struct o_coap_option *options, uint16_t opt_num,
		    enum AEAD_algorithm aead_alg, struct byte_array *kid,
		    struct byte_array *piv, struct byte_array *out)
{
	struct aad_array aad_array;

	aad_array.aad_array_oscore_version = 1;
	aad_array.aad_array_algorithms_alg_aead_choice =
		aad_array_algorithms_alg_aead_int_c;
	aad_array.aad_array_algorithms_alg_aead_int = (int32_t)aead_alg;
	aad_array.aad_array_request_kid.value = kid->ptr;
	aad_array.aad_array_request_kid.len = kid->len;
	aad_array.aad_array_request_piv.value = piv->ptr;
	aad_array.aad_array_request_piv.len = piv->len;

	PRINT_ARRAY("request_piv", piv->ptr, piv->len);
	PRINT_ARRAY("request_kid", kid->ptr, kid->len);

	/*
	 * Currently there are no I options defined.
	 * If at some later time I options are defined this implementation 
	 * must  be extended here. 
	 */
	aad_array.aad_array_options.len = 0;
	aad_array.aad_array_options.value = NULL;

	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_aad_array(out->ptr, out->len, &aad_array,
					 &payload_len_out),
		   0);

	out->len = (uint32_t)payload_len_out;
	PRINT_ARRAY("AAD", out->ptr, out->len);
	return ok;
}
