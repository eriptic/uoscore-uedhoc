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

#include "cbor/edhoc_encode_id_cred_x.h"

#include <zcbor_decode.h>

/* CBOR major types (RFC 8949 Section 3.1) */
#define CBOR_MAJOR_BSTR 2
#define CBOR_MAJOR_TSTR 3
#define CBOR_MAJOR_ARRAY 4
#define CBOR_MAJOR_MAP 5
#define CBOR_MAJOR_TAG 6

/**
 * @brief 			Encodes an ID_CRED_x containing a kid as a CBOR
 * 				map.
 * @param id 			The kid.
 * @param id_len 		Length of id.
 * @param[out] id_cred_x	The encoded value.
 * @retval			Ok or error.
 */
static enum err kid2id_cred(const void *id, uint32_t id_len,
			    struct byte_array *id_cred_x)
{
	struct id_cred_x_map map = { 0 };
	size_t payload_len_out;

	map.id_cred_x_map_kid_present = true;
	map.id_cred_x_map_kid.id_cred_x_map_kid_choice =
		id_cred_x_map_kid_bstr_c;
	map.id_cred_x_map_kid.id_cred_x_map_kid_bstr.value = id;
	map.id_cred_x_map_kid.id_cred_x_map_kid_bstr.len = id_len;

	TRY_EXPECT(cbor_encode_id_cred_x_map(id_cred_x->ptr, id_cred_x->len,
					     &map, &payload_len_out),
		   0);

	id_cred_x->len = (uint32_t)payload_len_out;

	return ok;
}

/**
 * @brief 			Reconstructs ID_CRED_x = { 4 : kid } from a kid
 * 				that was conveyed as a CBOR int.
 * @param kid_int 		The int from the plaintext.
 * @param[out] id_cred_x	The encoded ID_CRED_x.
 * @retval			Ok or error.
 */
static enum err kid_int2id_cred(int32_t kid_int, struct byte_array *id_cred_x)
{
	if (kid_int >= -24 && kid_int <= 23) {
		/* The int stands for the byte string that holds its CBOR
		 * encoding (RFC 9528 Section 3.3.2). */
		BYTE_ARRAY_NEW(kid_bstr, 1, 1);
		TRY(encode_int(&kid_int, 1, &kid_bstr));
		return kid2id_cred(kid_bstr.ptr, kid_bstr.len, id_cred_x);
	}

	/* Not a valid compact kid in RFC 9528; keep the int, as in drafts
	 * before RFC 9528. */
	struct id_cred_x_map map = { 0 };
	size_t payload_len_out;

	map.id_cred_x_map_kid_present = true;
	map.id_cred_x_map_kid.id_cred_x_map_kid_choice =
		id_cred_x_map_kid_int_c;
	map.id_cred_x_map_kid.id_cred_x_map_kid_int = kid_int;
	TRY_EXPECT(cbor_encode_id_cred_x_map(id_cred_x->ptr, id_cred_x->len,
					     &map, &payload_len_out),
		   0);
	id_cred_x->len = (uint32_t)payload_len_out;

	return ok;
}

/**
 * @brief 			Finds the end of the CBOR data item at the start
 * 				of a buffer. The plaintext comes from a peer
 * 				that is not authenticated yet and its nesting
 * 				depth is limited only by the message size, so
 * 				the item is walked without recursion.
 * @param[in] item 		The item.
 * @param[in] end 		The end of the buffer.
 * @param[out] item_end		The end of the item.
 * @retval			Ok or error.
 */
static enum err cbor_item_end(const uint8_t *item, const uint8_t *end,
			      const uint8_t **item_end)
{
	const uint8_t *p = item;
	uint64_t open_items = 1;

	while (open_items != 0) {
		if (p == end) {
			return cbor_decoding_error;
		}

		uint8_t major_type = (uint8_t)(*p >> 5);
		uint8_t additional = (uint8_t)(*p & 0x1f);
		uint64_t argument = additional;
		p++;

		/* Reserved values and indefinite lengths */
		if (additional > 27) {
			return cbor_decoding_error;
		}
		if (additional > 23) {
			size_t argument_len = (size_t)1 << (additional - 24);

			if ((size_t)(end - p) < argument_len) {
				return cbor_decoding_error;
			}
			argument = 0;
			for (size_t i = 0; i < argument_len; i++) {
				argument = (argument << 8) | *p++;
			}
		}

		size_t remaining = (size_t)(end - p);

		open_items--;
		if (major_type >= CBOR_MAJOR_BSTR &&
		    major_type <= CBOR_MAJOR_MAP && argument > remaining) {
			return cbor_decoding_error;
		}
		if (major_type == CBOR_MAJOR_BSTR ||
		    major_type == CBOR_MAJOR_TSTR) {
			p += argument;
		} else if (major_type == CBOR_MAJOR_ARRAY) {
			open_items += argument;
		} else if (major_type == CBOR_MAJOR_MAP) {
			open_items += 2 * argument;
		} else if (major_type == CBOR_MAJOR_TAG) {
			open_items++;
		}

		/* An item takes at least one byte */
		if (open_items > (size_t)(end - p)) {
			return cbor_decoding_error;
		}
	}

	*item_end = p;
	return ok;
}

enum err plaintext_split(struct byte_array *ptxt, struct byte_array *c_r,
			 struct byte_array *id_cred_x,
			 struct byte_array *sign_or_mac, struct byte_array *ead)
{
	const uint8_t *end = ptxt->ptr + ptxt->len;
	struct zcbor_string str;
	int32_t value;
	ZCBOR_STATE_D(state, 0, ptxt->ptr, ptxt->len, 4, 0);

	/*C_R is present only in plaintext 2*/
	if (c_r != NULL) {
		if (zcbor_bstr_decode(state, &str)) {
			TRY(_memcpy_s(c_r->ptr, c_r->len, str.value,
				      (uint32_t)str.len));
			c_r->len = (uint32_t)str.len;
		} else {
			/*provide C_R in encoded form if it was an int*/
			/*this is how it C_R was chosen by the responder*/
			TRY_EXPECT(zcbor_int32_decode(state, &value), true);
			TRY(c_x_int_encode(value, c_r));
		}
	}

	/*ID_CRED_x*/
	if (state->payload < end && (*state->payload >> 5) == CBOR_MAJOR_MAP) {
		/*A map is covered by the MAC as it was sent, keep it as is*/
		const uint8_t *id_cred_end;

		TRY(cbor_item_end(state->payload, end, &id_cred_end));
		uint32_t id_cred_len = (uint32_t)(id_cred_end - state->payload);

		TRY(_memcpy_s(id_cred_x->ptr, id_cred_x->len, state->payload,
			      id_cred_len));
		id_cred_x->len = id_cred_len;
		state->payload = id_cred_end;
	} else if (zcbor_bstr_decode(state, &str)) {
		/*Note that if ID_CRED_x contains a single 'kid' parameter,
		i.e., ID_CRED_x = { 4 : kid_x }, only the byte string kid_x
		is conveyed in the plaintext encoded as a bstr or int*/
		TRY(kid2id_cred(str.value, (uint32_t)str.len, id_cred_x));
	} else {
		TRY_EXPECT(zcbor_int32_decode(state, &value), true);
		TRY(kid_int2id_cred(value, id_cred_x));
	}

	TRY_EXPECT(zcbor_bstr_decode(state, &str), true);
	TRY(_memcpy_s(sign_or_mac->ptr, sign_or_mac->len, str.value,
		      (uint32_t)str.len));
	sign_or_mac->len = (uint32_t)str.len;

	if (zcbor_bstr_decode(state, &str)) {
		TRY(_memcpy_s(ead->ptr, ead->len, str.value,
			      (uint32_t)str.len));
		ead->len = (uint32_t)str.len;
	} else if (ead->len) {
		ead->len = 0;
	}

	return ok;
}
