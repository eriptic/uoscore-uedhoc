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
#include "edhoc/int_encode_decode.h"

#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "cbor/edhoc_decode_plaintext2.h"
#include "cbor/edhoc_decode_plaintext3.h"
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
		map.id_cred_x_map_kid_present = true;
		map.id_cred_x_map_kid.id_cred_x_map_kid_choice =
			id_cred_x_map_kid_int_c;
		map.id_cred_x_map_kid.id_cred_x_map_kid_int =
			*((const int32_t *)id);
		break;
	case x5chain:
		map.id_cred_x_map_x5chain_present = true;
		map.id_cred_x_map_x5chain.id_cred_x_map_x5chain.value = id;
		map.id_cred_x_map_x5chain.id_cred_x_map_x5chain.len = id_len;
		break;
	case x5t:
		map.id_cred_x_map_x5t_present = true;
		map.id_cred_x_map_x5t.id_cred_x_map_x5t_alg_choice =
			id_cred_x_map_x5t_alg_int_c;
		map.id_cred_x_map_x5t.id_cred_x_map_x5t_alg_int = algo;
		map.id_cred_x_map_x5t.id_cred_x_map_x5t_hash.value = id;
		map.id_cred_x_map_x5t.id_cred_x_map_x5t_hash.len = id_len;
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

static enum err plaintext2_split(struct byte_array *ptxt,
				 struct byte_array *c_r,
				 struct byte_array *id_cred_r,
				 struct byte_array *sign_or_mac,
				 struct byte_array *ead)
{
	size_t decode_len = 0;
	struct ptxt2 p;

	TRY_EXPECT(cbor_decode_ptxt2(ptxt->ptr, ptxt->len, &p, &decode_len), 0);

	/*decode C_R*/
	if (p.ptxt2_C_R_choice == ptxt2_C_R_bstr_c) {
		TRY(_memcpy_s(c_r->ptr, c_r->len, p.ptxt2_C_R_bstr.value,
			      (uint32_t)p.ptxt2_C_R_bstr.len));
		c_r->len = (uint32_t)p.ptxt2_C_R_bstr.len;
	} else {
		/*provide C_R in encoded form if it was an int*/
		/*this is how it C_R was chosen by the responder*/
		TRY(encode_int(&p.ptxt2_C_R_int, 1, c_r));
	}

	/*ID_CRED_R*/
	if (p.ptxt2_ID_CRED_R_choice == ptxt2_ID_CRED_R_map2_m_c) {
		if (p.ptxt2_ID_CRED_R_map2_m.map2_x5chain_present) {
			PRINT_MSG("ID_CRED_R is x5chain\n");
			TRY(id_cred_x_encode(
				x5chain, 0,
				p.ptxt2_ID_CRED_R_map2_m.map2_x5chain
					.map2_x5chain.value,
				(uint32_t)p.ptxt2_ID_CRED_R_map2_m.map2_x5chain
					.map2_x5chain.len,
				id_cred_r));
		}
		if (p.ptxt2_ID_CRED_R_map2_m.map2_x5t_present) {
			PRINT_MSG("ID_CRED_R is x5t\n");
			TRY(id_cred_x_encode(x5t,
					     p.ptxt2_ID_CRED_R_map2_m.map2_x5t
						     .map2_x5t_alg_int,
					     p.ptxt2_ID_CRED_R_map2_m.map2_x5t
						     .map2_x5t_hash.value,
					     (uint32_t)p.ptxt2_ID_CRED_R_map2_m
						     .map2_x5t.map2_x5t_hash.len,
					     id_cred_r));
		}
	} else {
		/*Note that if ID_CRED_x contains a single 'kid' parameter,
            i.e., ID_CRED_R = { 4 : kid_x }, only the byte string kid_x
            is conveyed in the plaintext encoded as a bstr or int*/
		if (p.ptxt2_ID_CRED_R_choice == ptxt2_ID_CRED_R_map2_m_c) {
			TRY(id_cred_x_encode(
				kid, 0, p.ptxt2_ID_CRED_R_bstr.value,
				(uint32_t)p.ptxt2_ID_CRED_R_bstr.len,
				id_cred_r));

		} else {
			int _kid = p.ptxt2_ID_CRED_R_int;
			TRY(id_cred_x_encode(kid, 0, &_kid, 1, id_cred_r));
		}
	}
	TRY(_memcpy_s(sign_or_mac->ptr, sign_or_mac->len,
		      p.ptxt2_SGN_or_MAC_2.value,
		      (uint32_t)p.ptxt2_SGN_or_MAC_2.len));
	sign_or_mac->len = (uint32_t)p.ptxt2_SGN_or_MAC_2.len;

	if (p.ptxt2_EAD_2_present == true) {
		TRY(_memcpy_s(ead->ptr, ead->len, p.ptxt2_EAD_2.value,
			      (uint32_t)p.ptxt2_EAD_2.len));
		ead->len = (uint32_t)p.ptxt2_EAD_2.len;
	} else {
		if (ead->len) {
			ead->len = 0;
		}
	}

	return ok;
}

static enum err plaintext3_split(struct byte_array *ptxt,
				 struct byte_array *id_cred_i,
				 struct byte_array *sign_or_mac,
				 struct byte_array *ead)
{
	size_t decode_len = 0;
	struct ptxt3 p;

	TRY_EXPECT(cbor_decode_ptxt3(ptxt->ptr, ptxt->len, &p, &decode_len), 0);

	/*ID_CRED_I*/
	if (p.ptxt3_ID_CRED_I_choice == ptxt3_ID_CRED_I_map3_m_c) {
		if (p.ptxt3_ID_CRED_I_map3_m.map3_x5chain_present) {
			PRINT_MSG("ID_CRED_I is x5chain\n");
			TRY(id_cred_x_encode(
				x5chain, 0,
				p.ptxt3_ID_CRED_I_map3_m.map3_x5chain
					.map3_x5chain.value,
				(uint32_t)p.ptxt3_ID_CRED_I_map3_m.map3_x5chain
					.map3_x5chain.len,
				id_cred_i));
		}
		if (p.ptxt3_ID_CRED_I_map3_m.map3_x5t_present) {
			PRINT_MSG("ID_CRED_I is x5t\n");
			TRY(id_cred_x_encode(x5t,
					     p.ptxt3_ID_CRED_I_map3_m.map3_x5t
						     .map3_x5t_alg_int,
					     p.ptxt3_ID_CRED_I_map3_m.map3_x5t
						     .map3_x5t_hash.value,
					     (uint32_t)p.ptxt3_ID_CRED_I_map3_m
						     .map3_x5t.map3_x5t_hash.len,
					     id_cred_i));
		}
	} else {
		/*Note that if ID_CRED_x contains a single 'kid' parameter,
            i.e., ID_CRED_I = { 4 : kid_x }, only the byte string kid_x
            is conveyed in the plaintext encoded as a bstr or int*/
		if (p.ptxt3_ID_CRED_I_choice == ptxt3_ID_CRED_I_map3_m_c) {
			TRY(id_cred_x_encode(
				kid, 0, p.ptxt3_ID_CRED_I_bstr.value,
				(uint32_t)p.ptxt3_ID_CRED_I_bstr.len,
				id_cred_i));

		} else {
			int _kid = p.ptxt3_ID_CRED_I_int;
			TRY(id_cred_x_encode(kid, 0, &_kid, 1, id_cred_i));
		}
	}
	TRY(_memcpy_s(sign_or_mac->ptr, sign_or_mac->len,
		      p.ptxt3_SGN_or_MAC_3.value,
		      (uint32_t)p.ptxt3_SGN_or_MAC_3.len));
	sign_or_mac->len = (uint32_t)p.ptxt3_SGN_or_MAC_3.len;

	if (p.ptxt3_EAD_3_present == true) {
		TRY(_memcpy_s(ead->ptr, ead->len, p.ptxt3_EAD_3.value,
			      (uint32_t)p.ptxt3_EAD_3.len));
		ead->len = (uint32_t)p.ptxt3_EAD_3.len;
	} else {
		if (ead->len) {
			ead->len = 0;
		}
	}
	return ok;
}

enum err plaintext_split(struct byte_array *ptxt, struct byte_array *c_r,
			 struct byte_array *id_cred_x,
			 struct byte_array *sign_or_mac, struct byte_array *ead)
{
	/*C_R is present only in plaintext 2*/
	if (c_r != NULL) {
		return plaintext2_split(ptxt, c_r, id_cred_x, sign_or_mac, ead);
	} else {
		return plaintext3_split(ptxt, id_cred_x, sign_or_mac, ead);
	}
}
