/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc.h"

#include "edhoc/th.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "cbor/edhoc_encode_data_2.h"
#include "cbor/edhoc_encode_th2.h"

/**
 * @brief   Setups a data structure used as input for th2, namely CBOR sequence
 *           H( G_Y, C_R, H(message_1) )
 * @param   hash_msg1 pointer to the hash of message 1
 * @param   hash_msg1_len length of hash_msg1
 * @param   g_y pointer to the public DH parameter
 * @param	g_y_len length of g_y
 * @param   c_r pointer to the conception identifier of the responder
 * @param	c_r_len length of c_r
 * @param   th2_input ouput buffer for the data structure
 * @param   th2_input_len length of th2_input
 */
static inline enum err th2_input_encode(uint8_t *hash_msg1,
					struct byte_array *g_y,
					struct byte_array *c_r,
					struct byte_array *th2_input)
{
	size_t payload_len_out;
	struct th2 th2;

	/*Encode hash_msg1*/
	th2._th2_hash_msg1.value = hash_msg1;
	th2._th2_hash_msg1.len = HASH_DEFAULT_SIZE;

	/*Encode G_Y*/
	th2._th2_G_Y.value = g_y->ptr;
	th2._th2_G_Y.len = g_y->len;

	/*Encode C_R as int or byte*/
	if (c_r->len == 1 && (c_r->ptr[0] < 0x18 ||
			      (0x1F < c_r->ptr[0] && c_r->ptr[0] <= 0x37))) {
		th2._th2_C_R_choice = _th2_C_R_int;
		TRY(decode_int(c_r->ptr, 1, &th2._th2_C_R_int));
	} else {
		th2._th2_C_R_choice = _th2_C_R_bstr;
		th2._th2_C_R_bstr.value = c_r->ptr;
		th2._th2_C_R_bstr.len = c_r->len;
	}
	TRY_EXPECT(cbor_encode_th2(th2_input->ptr, th2_input->len, &th2,
				   &payload_len_out),
		   0);

	/* Get the the total th2 length */
	th2_input->len = (uint32_t)payload_len_out;

	PRINT_ARRAY("Input to calculate TH_2 (CBOR Sequence)", th2_input->ptr,
		    th2_input->len);
	return ok;
}

/**
 * @brief   Setups a data structure used as input for th3 or th4
 * 
 * @param   th23 pointer to a th2/th3
 * @param   th23_len length of th23
 * @param   plaintext_23 Plaintext 2 or plaintext 3
 * @param   plaintext_23_len  length of plaintext_23
 * @param   th34_input data structure to be hashed for TH_3/4
 * @param   th34_input_len length of th34_input
 */
static enum err th34_input_encode(struct byte_array *th23,
				  struct byte_array *plaintext_23,
				  const struct byte_array *cred,
				  struct byte_array *th34_input)
{
	PRINT_ARRAY("th23", th23->ptr, th23->len);
	PRINT_ARRAY("plaintext_23", plaintext_23->ptr, plaintext_23->len);
	PRINT_ARRAY("cred", cred->ptr, cred->len);

	TRY(encode_bstr(th23, th34_input));
	uint32_t tmp_len = th34_input->len;

	TRY(_memcpy_s(th34_input->ptr + tmp_len,
		      th34_input->len - tmp_len - cred->len, plaintext_23->ptr,
		      plaintext_23->len));

	tmp_len += plaintext_23->len;

	TRY(_memcpy_s(th34_input->ptr + tmp_len, th34_input->len - tmp_len,
		      cred->ptr, cred->len));

	th34_input->len = tmp_len + cred->len;

	PRINT_ARRAY("Input to calculate TH_3/TH_4 (CBOR Sequence)",
		    th34_input->ptr, th34_input->len);
	return ok;
}

/**
 * @brief Computes TH_3/TH4. Where: 
 * 				TH_3 = H(TH_2, PLAINTEXT_2)
 * 				TH_4 = H(TH_3, PLAINTEXT_3)
 * 
 * 
 * @param alg the hash algorithm to be used
 * @param th23 th2 if we compute TH_3 and th3 if we compute TH_4
 * @param th23_len length of th23
 * @param plaintext_23 the plaintext
 * @param plaintext_33_len length of plaintext_23
 * @param th34 the result
 * @return enum err 
 */
enum err th34_calculate(enum hash_alg alg, struct byte_array *th23,
			struct byte_array *plaintext_23,
			const struct byte_array *cred, uint8_t *th34)
{
	uint32_t th34_input_len =
		th23->len + plaintext_23->len + cred->len + ENCODING_OVERHEAD;
	BYTE_ARRAY_NEW(th34_input, TH34_INPUT_DEFAULT_SIZE, th34_input_len);

	TRY(th34_input_encode(th23, plaintext_23, cred, &th34_input));
	TRY(hash(alg, &th34_input, th34));
	PRINT_ARRAY("TH34", th34, HASH_DEFAULT_SIZE);
	return ok;
}

enum err th2_calculate(enum hash_alg alg, uint8_t *msg1_hash,
		       struct byte_array *g_y, struct byte_array *c_r,
		       uint8_t *th2)
{
	BYTE_ARRAY_NEW(th2_input, TH2_INPUT_DEFAULT_SIZE,
		       TH2_INPUT_DEFAULT_SIZE);
	PRINT_ARRAY("hash_msg1_raw", msg1_hash, HASH_DEFAULT_SIZE);
	TRY(th2_input_encode(msg1_hash, g_y, c_r, &th2_input));
	TRY(hash(alg, &th2_input, th2));
	PRINT_ARRAY("TH2", th2, HASH_DEFAULT_SIZE);
	return ok;
}
