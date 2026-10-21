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
#include <stdbool.h>

#include "edhoc/retrieve_cred.h"
#include "edhoc/signature_or_mac_msg.h"
#include "edhoc/plaintext.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/buffer_sizes.h"
#include "edhoc/int_encode_decode.h"

#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "cbor/edhoc_decode_id_cred_x.h"
#include "cbor/edhoc_encode_int_type.h"

enum err id_cred2kid(const struct byte_array *id_cred, struct byte_array *kid)
{
	struct id_cred_x_map map = { 0 };
	size_t payload_len_out;
	size_t decode_len = 0;
	TRY_EXPECT(cbor_decode_id_cred_x_map(id_cred->ptr, id_cred->len, &map,
					     &decode_len),
		   0);

	/* The compact encoding applies only if ID_CRED_x contains a single
	 * 'kid' parameter (RFC 9528 Section 3.5.3.2). */
	bool kid_only = map.id_cred_x_map_kid_present &&
			!map.id_cred_x_map_x5bag_present &&
			!map.id_cred_x_map_x5chain_present &&
			!map.id_cred_x_map_x5t_present &&
			!map.id_cred_x_map_x5u_present &&
			!map.id_cred_x_map_c5b_present &&
			!map.id_cred_x_map_c5c_present &&
			!map.id_cred_x_map_c5t_present &&
			!map.id_cred_x_map_c5u_present;

	if (!kid_only) {
		kid->len = 0;
		return ok;
	}

	if (map.id_cred_x_map_kid.id_cred_x_map_kid_choice ==
	    id_cred_x_map_kid_int_c) {
		/* kid given as an int, as in drafts before RFC 9528 */
		TRY_EXPECT(
			cbor_encode_int_type_i(
				kid->ptr, kid->len,
				&map.id_cred_x_map_kid.id_cred_x_map_kid_int,
				&payload_len_out),
			ZCBOR_SUCCESS);
		kid->len = (uint32_t)payload_len_out;
		return ok;
	}

	/* A kid byte string that is the CBOR encoding of an int in -24..23 is
	 * sent as that int, any other kid as a byte string (RFC 9528 Section
	 * 3.3.2). */
	const struct zcbor_string *kid_str =
		&map.id_cred_x_map_kid.id_cred_x_map_kid_bstr;
	BYTE_ARRAY_NEW(kid_bstr, KID_SIZE, (uint32_t)kid_str->len);
	TRY(_memcpy_s(kid_bstr.ptr, kid_bstr.len, kid_str->value,
		      (uint32_t)kid_str->len));
	if (c_x_is_encoded_int(&kid_bstr)) {
		TRY(_memcpy_s(kid->ptr, kid->len, kid_bstr.ptr, kid_bstr.len));
		kid->len = kid_bstr.len;
	} else {
		TRY(encode_bstr(&kid_bstr, kid));
	}

	return ok;
}
