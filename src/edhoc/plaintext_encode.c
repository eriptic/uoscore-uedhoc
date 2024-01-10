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

#include "edhoc/retrieve_cred.h"
#include "edhoc/signature_or_mac_msg.h"
#include "edhoc/plaintext.h"
#include "edhoc/bstr_encode_decode.h"

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

	if (map.id_cred_x_map_kid_present) {
		TRY_EXPECT(
			cbor_encode_int_type_i(
				kid->ptr, kid->len,
				&map.id_cred_x_map_kid.id_cred_x_map_kid_int,
				&payload_len_out),
			ZCBOR_SUCCESS);
		kid->len = (uint32_t)payload_len_out;
	} else {
		kid->len = 0;
	}

	return ok;
}
