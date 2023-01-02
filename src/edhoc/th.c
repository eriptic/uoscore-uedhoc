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
					uint32_t hash_msg1_len, uint8_t *g_y,
					uint32_t g_y_len, uint8_t *c_r,
					uint32_t c_r_len, uint8_t *th2_input,
					uint32_t *th2_input_len)
{
	size_t payload_len_out;
	struct th2 th2;

	/*Encode hash_msg1*/
	th2._th2_hash_msg1.value = hash_msg1;
	th2._th2_hash_msg1.len = hash_msg1_len;

	/*Encode G_Y*/
	th2._th2_G_Y.value = g_y;
	th2._th2_G_Y.len = g_y_len;

	/*Encode C_R as int or byte*/
	if (c_r_len == 1 && (c_r[0] < 0x18 ||
			     (0x1F < c_r[0] && c_r[0] <= 0x37))) {
		th2._th2_C_R_choice = _th2_C_R_int;
		TRY(decode_int(c_r, 1, &th2._th2_C_R_int));
	} else {
		th2._th2_C_R_choice = _th2_C_R_bstr;
		th2._th2_C_R_bstr.value = c_r;
		th2._th2_C_R_bstr.len = c_r_len;
	}
	TRY_EXPECT(cbor_encode_th2(th2_input, *th2_input_len, &th2,
				   &payload_len_out),
		   true);

	/* Get the the total th2 length */
	*th2_input_len = (uint32_t)payload_len_out;

	PRINT_ARRAY("Input to calculate TH_2 (CBOR Sequence)", th2_input,
		    *th2_input_len);
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
static enum err th34_input_encode(uint8_t *th23, uint32_t th23_len,
				  uint8_t *plaintext_23,
				  uint32_t plaintext_23_len,
				  uint8_t *cred,
				  uint32_t cred_len,
				  uint8_t *th34_input, uint32_t *th34_input_len)
{
	TRY(check_buffer_size(*th34_input_len, th23_len + 2));

	uint32_t th23_encoded_len = *th34_input_len;
	TRY(encode_byte_string(th23, th23_len, th34_input, &th23_encoded_len));
    
	TRY(_memcpy_s(th34_input + th23_encoded_len, *th34_input_len - th23_encoded_len - cred_len,
                  plaintext_23, plaintext_23_len));
    
	TRY(_memcpy_s(th34_input + th23_encoded_len + plaintext_23_len,
                  *th34_input_len - th23_encoded_len - plaintext_23_len, cred, cred_len));
    
	*th34_input_len = th23_encoded_len + plaintext_23_len + cred_len;

	PRINT_ARRAY("Input to calculate TH_3/TH_4 (CBOR Sequence)", th34_input,
		    *th34_input_len);
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
static enum err th34_calculate(enum hash_alg alg, 
					uint8_t *th23, uint32_t th23_len, 
					uint8_t *plaintext_23, uint32_t plaintext_23_len, 
					uint8_t *cred, uint32_t cred_len, 
					uint8_t *th34)
{
	uint32_t th34_input_len =
		th23_len + plaintext_23_len + cred_len + ENCODING_OVERHEAD;
	TRY(check_buffer_size(TH34_INPUT_DEFAULT_SIZE, th34_input_len));
	uint8_t th34_input[TH34_INPUT_DEFAULT_SIZE];

	TRY(th34_input_encode(th23, th23_len, plaintext_23, plaintext_23_len,
			      cred, cred_len, th34_input, &th34_input_len));
	TRY(hash(alg, th34_input, th34_input_len, th34));
	PRINT_ARRAY("TH34", th34, HASH_DEFAULT_SIZE);
	return ok;
}

enum err th2_calculate(enum hash_alg alg, uint8_t *msg1_hash,
		       uint8_t *g_y, uint32_t g_y_len, uint8_t *c_r,
		       uint32_t c_r_len, uint8_t *th2)
{
	uint8_t th2_input[TH2_INPUT_DEFAULT_SIZE];
	uint32_t th2_input_len = sizeof(th2_input);

	PRINT_ARRAY("hash_msg1_raw", msg1_hash, HASH_DEFAULT_SIZE);
	TRY(th2_input_encode(msg1_hash, HASH_DEFAULT_SIZE, g_y, g_y_len, c_r,
			     c_r_len, th2_input, &th2_input_len));
	TRY(hash(alg, th2_input, th2_input_len, th2));
	PRINT_ARRAY("TH2", th2, HASH_DEFAULT_SIZE);
	return ok;
}

enum err th3_calculate(enum hash_alg alg, uint8_t *th2, uint32_t th2_len,
		       uint8_t *plaintext_2, uint32_t plaintext_2_len,
			   uint8_t *cred_r, uint32_t cred_r_len,
		       uint8_t *th3)
{
	return th34_calculate(alg, th2, th2_len, plaintext_2, plaintext_2_len,
				  cred_r, cred_r_len, th3);
}

enum err th4_calculate(enum hash_alg alg, uint8_t *th3, uint32_t th3_len,
		       uint8_t *plaintext_3, uint32_t plaintext_3_len,
			   uint8_t *cred_i, uint32_t cred_i_len,
		       uint8_t *th4)
{
	return th34_calculate(alg, th3, th3_len, plaintext_3, plaintext_3_len, 
				  cred_i, cred_i_len, th4);
}
