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
#include "edhoc/plaintext.h"
#include "edhoc/signature_or_mac_msg.h"

#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "cbor/edhoc_decode_plaintext.h"
#include "cbor/edhoc_encode_id_cred_x.h"

/**
 * @brief 			Encodes ID_CRED_x as a CBOR map.
 * @param label 		The CBOR map label.
 * @param algo 			The EDHOC hash algorithm used in x5t. This 
 * 				parameter can take any other value when xchain 
 * 				or kid are used.
 * @param id 			The actual credential identifier.
 * @param id_len 		Length of id.
 * @param[out] id_cred_x	The encoded value.
 * @retval			Ok or error.
 */
static enum err id_cred_x_encode(enum id_cred_x_label label, int algo,
				 const void *id, uint32_t id_len,
				 struct byte_array *id_cred_x)
{
	struct id_cred_x_map map = { 0 };
	size_t payload_len_out;

	switch (label) {
	case kid:
		//todo update that to v15
		map._id_cred_x_map_kid_present = true;
		map._id_cred_x_map_kid._id_cred_x_map_kid_choice =
			_id_cred_x_map_kid_int;
		map._id_cred_x_map_kid._id_cred_x_map_kid_int =
			*((const int32_t *)id);
		break;
	case x5chain:
		map._id_cred_x_map_x5chain_present = true;
		map._id_cred_x_map_x5chain._id_cred_x_map_x5chain.value = id;
		map._id_cred_x_map_x5chain._id_cred_x_map_x5chain.len = id_len;
		break;
	case x5t:
		map._id_cred_x_map_x5t_present = true;
		map._id_cred_x_map_x5t._id_cred_x_map_x5t_alg_choice =
			_id_cred_x_map_x5t_alg_int;
		map._id_cred_x_map_x5t._id_cred_x_map_x5t_alg_int = algo;
		map._id_cred_x_map_x5t._id_cred_x_map_x5t_hash.value = id;
		map._id_cred_x_map_x5t._id_cred_x_map_x5t_hash.len = id_len;
		break;
	default:
		break;
	}

	TRY_EXPECT(cbor_encode_id_cred_x_map(id_cred_x->ptr, id_cred_x->len,
					     &map, &payload_len_out),
		   0);

	id_cred_x->len = (uint32_t)payload_len_out;

	return ok;
}

enum err plaintext_split(struct byte_array *ptxt, struct byte_array *id_cred_x,
			 struct byte_array *sign_or_mac, struct byte_array *ad)
{
	size_t decode_len = 0;
	struct plaintext p;

	TRY_EXPECT(cbor_decode_plaintext(ptxt->ptr, ptxt->len, &p, &decode_len),
		   0);

	/*ID_CRED_x*/
	if (p._plaintext_ID_CRED_x_choice == _plaintext_ID_CRED_x__map) {
		if (p._plaintext_ID_CRED_x__map._map_x5chain_present) {
			PRINT_MSG(
				"ID_CRED of the other party has label x5chain\n");
			TRY(id_cred_x_encode(
				x5chain, 0,
				p._plaintext_ID_CRED_x__map._map_x5chain
					._map_x5chain.value,
				(uint32_t)p._plaintext_ID_CRED_x__map
					._map_x5chain._map_x5chain.len,
				id_cred_x));
		}
		if (p._plaintext_ID_CRED_x__map._map_x5t_present) {
			PRINT_MSG("ID_CRED of the other party has label x5t\n");
			TRY(id_cred_x_encode(
				x5t,
				p._plaintext_ID_CRED_x__map._map_x5t
					._map_x5t_alg_int,
				p._plaintext_ID_CRED_x__map._map_x5t
					._map_x5t_hash.value,
				(uint32_t)p._plaintext_ID_CRED_x__map._map_x5t
					._map_x5t_hash.len,
				id_cred_x));
		}
	} else {
		/*Note that if ID_CRED_x contains a single 'kid' parameter,
            i.e., ID_CRED_R = { 4 : kid_x }, only the byte string kid_x
            is conveyed in the plaintext encoded as a bstr or int*/
		if (p._plaintext_ID_CRED_x_choice ==
		    _plaintext_ID_CRED_x__map) {
			TRY(id_cred_x_encode(
				kid, 0, p._plaintext_ID_CRED_x_bstr.value,
				(uint32_t)p._plaintext_ID_CRED_x_bstr.len,
				id_cred_x));

		} else {
			int _kid = p._plaintext_ID_CRED_x_int;
			TRY(id_cred_x_encode(kid, 0, &_kid, 1, id_cred_x));
		}
	}
	TRY(_memcpy_s(sign_or_mac->ptr, sign_or_mac->len,
		      p._plaintext_SGN_or_MAC_x.value,
		      (uint32_t)p._plaintext_SGN_or_MAC_x.len));
	sign_or_mac->len = (uint32_t)p._plaintext_SGN_or_MAC_x.len;

	if (p._plaintext_AD_x_present == true) {
		TRY(_memcpy_s(ad->ptr, ad->len, p._plaintext_AD_x.value,
			      (uint32_t)p._plaintext_AD_x.len));
		ad->len = (uint32_t)p._plaintext_AD_x.len;
	} else {
		if (ad->len) {
			ad->len = 0;
		}
	}

	return ok;
}
