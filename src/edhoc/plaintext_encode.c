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

#include "edhoc.h"

#include "edhoc/retrieve_cred.h"
#include "edhoc/signature_or_mac_msg.h"
#include "edhoc/plaintext.h"

#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "cbor/edhoc_decode_id_cred_x.h"
#include "cbor/edhoc_encode_int_type.h"

enum err id_cred2kid(const uint8_t *id_cred, uint32_t id_cred_len,
		     uint8_t *_kid, uint32_t *kid_len)
{
	struct id_cred_x_map map;
	size_t payload_len_out;
	size_t decode_len = 0;
	TRY_EXPECT(cbor_decode_id_cred_x_map(id_cred, id_cred_len, &map,
					     &decode_len),
		   true);

	if (map._id_cred_x_map_kid_present != 0) {
		// if (map._id_cred_x_map_kid._id_cred_x_map_kid.len == 1) {
		// 	int32_t i =
		// 		*map._id_cred_x_map_kid._id_cred_x_map_kid.value;
		// 	ok = cbor_encode_int_type_i(_kid, *kid_len, &i,
		// 				    &payload_len_out);
		// 	if (!ok) {
		// 		return cbor_encoding_error;
		// 	}
		// 	*kid_len = payload_len_out;
		// } else {
		// 	r = _memcpy_s(
		// 		_kid, *kid_len,
		// 		map._id_cred_x_map_kid._id_cred_x_map_kid.value,
		// 		map._id_cred_x_map_kid._id_cred_x_map_kid.len);
		// 	if (r != ok) {
		// 		return r;
		// 	}
		// 	*kid_len =
		// 		map._id_cred_x_map_kid._id_cred_x_map_kid.len;
		// }
		//*_kid = map._id_cred_x_map_kid._id_cred_x_map_kid;
		TRY_EXPECT(cbor_encode_int_type_i(
				   _kid, *kid_len,
				   &map._id_cred_x_map_kid._id_cred_x_map_kid,
				   &payload_len_out),
			   true);
		*kid_len = (uint32_t) payload_len_out;
	} else {
		*kid_len = 0;
	}

	return ok;
}

enum err plaintext_encode(const uint8_t *id_cred, uint32_t id_cred_len,
			  const uint8_t *sgn_or_mac, uint32_t sgn_or_mac_len,
			  const uint8_t *ad, uint32_t ad_len,
			  uint8_t *plaintext, uint32_t *plaintext_len)
{
	uint32_t l;
	uint32_t enc_sgn_or_mac_len = sgn_or_mac_len + 2;
	uint8_t kid_buf[KID_DEFAULT_SIZE];
	uint32_t kid_len = sizeof(kid_buf);
	TRY(id_cred2kid(id_cred, id_cred_len, kid_buf, &kid_len));

	PRINT_ARRAY("kid", kid_buf, kid_len);
	if (kid_len != 0) {
		/*id cred contains a kid*/
		TRY(_memcpy_s(plaintext, *plaintext_len, kid_buf, kid_len));
		l = kid_len;
	} else {
		TRY(_memcpy_s(plaintext, *plaintext_len, id_cred, id_cred_len));
		l = id_cred_len;
	}

	TRY(encode_byte_string(sgn_or_mac, sgn_or_mac_len, plaintext + l,
			       &enc_sgn_or_mac_len));

	TRY(_memcpy_s(plaintext + l + enc_sgn_or_mac_len,
		      *plaintext_len - l - enc_sgn_or_mac_len, ad, ad_len));

	*plaintext_len = l + enc_sgn_or_mac_len + ad_len;

	return ok;
}
