/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/buffer_sizes.h"

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
 * @brief   			Setups a data structure used as input for th2, 
 * 				namely CBOR sequence H( G_Y, C_R, H(message_1)).
 *
 * @param[in] hash_msg1 	Hash of message 1.
 * @param[in] g_y 		Ephemeral public DH key.
 * @param[in] c_r 		Conception identifier of the responder.
 * @param[out] th2_input	The result.
 * @retval			Ok or error.
 */
static inline enum err th2_input_encode(struct byte_array *hash_msg1,
					struct byte_array *g_y,
					struct byte_array *c_r,
					struct byte_array *th2_input)
{
	size_t payload_len_out;
	struct th2 th2;

	/*Encode hash_msg1*/
	th2.th2_hash_msg1.value = hash_msg1->ptr;
	th2.th2_hash_msg1.len = hash_msg1->len;

	/*Encode G_Y*/
	th2.th2_G_Y.value = g_y->ptr;
	th2.th2_G_Y.len = g_y->len;

	/*Encode C_R as int or byte*/
	if (c_r->len == 1 && (c_r->ptr[0] < 0x18 ||
			      (0x1F < c_r->ptr[0] && c_r->ptr[0] <= 0x37))) {
		th2.th2_C_R_choice = th2_C_R_int_c;
		TRY(decode_int(c_r, &th2.th2_C_R_int));
	} else {
		th2.th2_C_R_choice = th2_C_R_bstr_c;
		th2.th2_C_R_bstr.value = c_r->ptr;
		th2.th2_C_R_bstr.len = c_r->len;
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
 * @brief   			Setups a data structure used as input for 
 * 				th3 or th4.
 * 
 * @param[in] th23 		th2 or th3.
 * @param[in] plaintext_23 	Plaintext 2 or plaintext 3.
 * @param[in] cred		The credential.
 * @param[out] th34_input 	The result.
 * @retval			Ok or error code.
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
 * @brief 			Computes TH_3 or TH4. Where: 
 * 				TH_3 = H(TH_2, PLAINTEXT_2)
 * 				TH_4 = H(TH_3, PLAINTEXT_3)
 * 
 * @param alg 			The hash algorithm to be used.
 * @param[in] th23 		th2 if we compute TH_3, th3 if we compute TH_4.
 * @param[in] plaintext_23 	The plaintext.
 * @param[in] cred		The credential.
 * @param[out] th34 		The result.
 * @return 			Ok or error. 
 */
enum err th34_calculate(enum hash_alg alg, struct byte_array *th23,
			struct byte_array *plaintext_23,
			const struct byte_array *cred, struct byte_array *th34)
{
	uint32_t th34_input_len = th23->len + plaintext_23->len + cred->len + 2;
	BYTE_ARRAY_NEW(th34_input, TH34_INPUT_SIZE, th34_input_len);

	TRY(th34_input_encode(th23, plaintext_23, cred, &th34_input));
	TRY(hash(alg, &th34_input, th34));
	PRINT_ARRAY("TH34", th34->ptr, th34->len);
	return ok;
}

enum err th2_calculate(enum hash_alg alg, struct byte_array *msg1_hash,
		       struct byte_array *g_y, struct byte_array *c_r,
		       struct byte_array *th2)
{
	BYTE_ARRAY_NEW(th2_input, TH2_DEFAULT_SIZE,
		       g_y->len + c_r->len + th2->len + ENCODING_OVERHEAD);
	PRINT_ARRAY("hash_msg1_raw", msg1_hash->ptr, msg1_hash->len);
	TRY(th2_input_encode(msg1_hash, g_y, c_r, &th2_input));
	TRY(hash(alg, &th2_input, th2));
	PRINT_ARRAY("TH2", th2->ptr, th2->len);
	return ok;
}
