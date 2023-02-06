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

#include "edhoc/okm.h"
#include "edhoc/ciphertext.h"
#include "edhoc/signature_or_mac_msg.h"
#include "edhoc/plaintext.h"
#include "edhoc/associated_data_encode.h"
#include "edhoc/suites.h"
#include "edhoc/bstr_encode_decode.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"

/**
 * @brief Xors two arrays
 * 
 * @param in1 an input array
 * @param in2 an input array
 * @param len the lenhgt of the arrays
 * @param out the result
 */
static inline void xor_arrays(const uint8_t *in1, const uint8_t *in2,
			      uint32_t len, uint8_t *out)
{
	for (uint32_t i = 0; i < len; i++) {
		out[i] = in1[i] ^ in2[i];
	}
}

/**
 * @brief Encrypts a plaintext or decrypts a cyphertext
 * 
 * @param ctxt CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4
 * @param op ENCRYPT or DECRYPT
 * @param in ciphertext or plaintext 
 * @param in_len lenhgt of in
 * @param key the key used of encrption/decryption
 * @param key_len lenhgt of key
 * @param nonce AEAD nonce
 * @param nonce_len lenhgt of nonce
 * @param aad additional authenticated data for AEAD
 * @param aad_len lenhgt of aad
 * @param out the result
 * @param out_len lenhgt of out
 * @param tag AEAD authentication tag
 * @param tag_len lenhgt of tag
 * @return enum err 
 */
static enum err ciphertext_encrypt_decrypt(
	enum ciphertext ctxt, enum aes_operation op, const uint8_t *in,
	const uint32_t in_len, const uint8_t *key, const uint32_t key_len,
	uint8_t *nonce, const uint32_t nonce_len, const uint8_t *aad,
	const uint32_t aad_len, uint8_t *out, const uint32_t out_len,
	uint8_t *tag, const uint32_t tag_len)
{
	if (ctxt == CIPHERTEXT2) {
		xor_arrays(in, key, key_len, out);
	} else {
		PRINT_ARRAY("in", in, in_len);
		TRY(aead(op, in, in_len, key, key_len, nonce, nonce_len, aad,
			 aad_len, out, out_len, tag, tag_len));
	}
	return ok;
}

/**
 * @brief Computes the keystream for ciphertext 2 and the key and IV for 
 *        ciphertexts 3 and 4. 
 * 
 * @param ctxt CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4
 * @param edhoc_hash the hash algorithm used in the current edhoc run
 * @param prk pseudoramdom key
 * @param prk_len lenhgt of prk
 * @param th thraskript hash
 * @param th_len lenhgt of th
 * @param key the generated key
 * @param key_len lenhgt of key
 * @param iv the generated iv
 * @param iv_len lenhgt of iv
 * @return enum err 
 */
static enum err key_gen(enum ciphertext ctxt, enum hash_alg edhoc_hash,
			uint8_t *prk, uint32_t prk_len, uint8_t *th,
			uint32_t th_len, uint8_t *key, uint32_t key_len,
			uint8_t *iv, uint32_t iv_len)
{
	switch (ctxt) {
	case CIPHERTEXT2:
		TRY(edhoc_kdf(edhoc_hash, prk, prk_len, KEYSTREAM_2, th, th_len,
			      key_len, key));
		PRINT_ARRAY("KEYSTREAM_2", key, key_len);
		break;

	case CIPHERTEXT3:
		TRY(edhoc_kdf(edhoc_hash, prk, prk_len, K_3, th, th_len,
			      key_len, key));

		PRINT_ARRAY("K_3", key, key_len);

		TRY(edhoc_kdf(edhoc_hash, prk, prk_len, IV_3, th, th_len,
			      iv_len, iv));
		PRINT_ARRAY("IV_3", iv, iv_len);
		break;

	case CIPHERTEXT4:
		TRY(edhoc_kdf(edhoc_hash, prk, prk_len, K_4, th, th_len,
			      key_len, key));
		PRINT_ARRAY("K_4", key, key_len);
		TRY(edhoc_kdf(edhoc_hash, prk, prk_len, IV_4, th, th_len,
			      iv_len, iv));
		PRINT_ARRAY("IV_4", iv, iv_len);
		break;
	}
	return ok;
}

enum err ciphertext_decrypt_split(enum ciphertext ctxt, struct suite *suite,
				  uint8_t *id_cred, uint32_t *id_cred_len,
				  uint8_t *signature_or_mac,
				  uint32_t *signature_or_mac_len, uint8_t *ead,
				  uint32_t *ead_len, uint8_t *prk,
				  uint32_t prk_len, uint8_t *th,
				  uint32_t th_len, uint8_t *ciphertext,
				  uint32_t ciphertext_len, uint8_t *plaintext,
				  uint32_t plaintext_len)
{
	/*generate key and iv (no iv in for ciphertext 2)*/
	uint32_t key_len;
	uint8_t key[CIPHERTEXT2_DEFAULT_SIZE];
	if (ctxt == CIPHERTEXT2) {
		key_len = ciphertext_len;
	} else {
		key_len = get_aead_key_len(suite->edhoc_aead);
	}
	TRY(check_buffer_size(CIPHERTEXT2_DEFAULT_SIZE, key_len));

	uint32_t iv_len = get_aead_iv_len(suite->edhoc_aead);
	TRY(check_buffer_size(AEAD_IV_DEFAULT_SIZE, iv_len));
	uint8_t iv[AEAD_IV_DEFAULT_SIZE];

	TRY(key_gen(ctxt, suite->edhoc_hash, prk, prk_len, th, th_len, key,
		    key_len, iv, iv_len));

	/*Associated data*/
	uint8_t associated_data[ASSOCIATED_DATA_DEFAULT_SIZE];
	uint32_t associated_data_len = sizeof(associated_data);
	TRY(associated_data_encode(th, th_len, (uint8_t *)&associated_data,
				   &associated_data_len));

	PRINT_ARRAY("associated_data", associated_data, associated_data_len);

	uint32_t tag_len = get_aead_mac_len(suite->edhoc_aead);
	// uint32_t plaintext_len = ciphertext_len;
	if (ctxt != CIPHERTEXT2) {
		if (plaintext_len < tag_len) {
			return error_message_received;
		}
		plaintext_len -= tag_len;
	}
	// TRY(check_buffer_size(PLAINTEXT_DEFAULT_SIZE, plaintext_len));
	// uint8_t plaintext[PLAINTEXT_DEFAULT_SIZE];
	TRY(ciphertext_encrypt_decrypt(
		ctxt, DECRYPT, ciphertext, ciphertext_len, key, key_len, iv,
		iv_len, associated_data, associated_data_len, plaintext,
		plaintext_len, ciphertext - tag_len, tag_len));

	PRINT_ARRAY("plaintext", plaintext, plaintext_len);

	if (ctxt == CIPHERTEXT4 && plaintext_len != 0) {
		TRY(decode_byte_string(plaintext, plaintext_len, ead, ead_len));
		PRINT_ARRAY("EAD_4", ead, *ead_len);
	} else if (ctxt == CIPHERTEXT4 && plaintext_len == 0) {
		ead = NULL;
		*ead_len = 0;
		PRINT_MSG("No EAD_4\n");
	} else {
		TRY(plaintext_split(plaintext, plaintext_len, id_cred,
				    id_cred_len, signature_or_mac,
				    signature_or_mac_len, ead, ead_len));
		PRINT_ARRAY("ID_CRED", id_cred, *id_cred_len);
		PRINT_ARRAY("sign_or_mac", signature_or_mac,
			    *signature_or_mac_len);
		if (ead_len != NULL && *ead_len != 0) {
			PRINT_ARRAY("ead", ead, *ead_len);
		}
	}

	return ok;
}

enum err ciphertext_gen(enum ciphertext ctxt, struct suite *suite,
			uint8_t *id_cred, uint32_t id_cred_len,
			uint8_t *signature_or_mac,
			uint32_t signature_or_mac_len, uint8_t *ead,
			uint32_t ead_len, uint8_t *prk, uint32_t prk_len,
			uint8_t *th, uint32_t th_len, uint8_t *ciphertext,
			uint32_t *ciphertext_len, uint8_t *plaintext,
			uint32_t *plaintext_len)
{
	TRY(check_buffer_size(SGN_OR_MAC_DEFAULT_SIZE,
			      signature_or_mac_len + 2));
	uint8_t signature_or_mac_enc[SGN_OR_MAC_DEFAULT_SIZE];
	uint32_t signature_or_mac_enc_len = signature_or_mac_len + 2;
	TRY(encode_byte_string(signature_or_mac, signature_or_mac_len,
			       signature_or_mac_enc,
			       &signature_or_mac_enc_len));

	if (ctxt != CIPHERTEXT4) {
		uint8_t kid_buf[KID_DEFAULT_SIZE];
		uint32_t kid_len = sizeof(kid_buf);
		TRY(id_cred2kid(id_cred, id_cred_len, kid_buf, &kid_len));

		PRINT_ARRAY("kid", kid_buf, kid_len);

		if (kid_len != 0) {
			/*id_cred_x is a KID*/
			TRY(_memcpy_s(plaintext, *plaintext_len, kid_buf,
				      kid_len));

			TRY(_memcpy_s(plaintext + kid_len,
				      *plaintext_len - kid_len,
				      signature_or_mac_enc,
				      signature_or_mac_enc_len));

			*plaintext_len = signature_or_mac_enc_len + kid_len;
		} else {
			/*id_cred_x is NOT a KID*/
			TRY(_memcpy_s(plaintext, *plaintext_len, id_cred,
				      id_cred_len));

			TRY(_memcpy_s(plaintext + id_cred_len,
				      *plaintext_len - id_cred_len,
				      signature_or_mac_enc,
				      signature_or_mac_enc_len));

			*plaintext_len = id_cred_len + signature_or_mac_enc_len;
		}
	} else {
		*plaintext_len = 0;
	}
	if (ead_len > 0) {
		TRY(_memcpy_s(plaintext + *plaintext_len,
			      (uint32_t)sizeof(plaintext) - *plaintext_len, ead,
			      ead_len));

		*plaintext_len += ead_len;
	}

	PRINT_ARRAY("plaintext", plaintext, *plaintext_len);

	/*generate key and iv (no iv in for ciphertext 2)*/
	uint32_t key_len;
	uint8_t key[CIPHERTEXT2_DEFAULT_SIZE];
	if (ctxt == CIPHERTEXT2) {
		key_len = *plaintext_len;
	} else {
		key_len = get_aead_key_len(suite->edhoc_aead);
	}
	TRY(check_buffer_size(CIPHERTEXT2_DEFAULT_SIZE, key_len));

	uint32_t iv_len = get_aead_iv_len(suite->edhoc_aead);
	TRY(check_buffer_size(AEAD_IV_DEFAULT_SIZE, iv_len));
	uint8_t iv[AEAD_IV_DEFAULT_SIZE];

	TRY(key_gen(ctxt, suite->edhoc_hash, prk, prk_len, th, th_len, key,
		    key_len, iv, iv_len));

	/*encrypt*/
	uint8_t aad[ASSOCIATED_DATA_DEFAULT_SIZE];
	uint32_t aad_len = sizeof(aad);
	uint32_t tag_len = get_aead_mac_len(suite->edhoc_aead);
	TRY(check_buffer_size(MAC_DEFAULT_SIZE, tag_len));
	uint8_t tag[MAC_DEFAULT_SIZE];
	if (ctxt != CIPHERTEXT2) {
		/*Associated data*/
		TRY(associated_data_encode(th, th_len, aad, &aad_len));
		PRINT_ARRAY("aad_data", aad, aad_len);
	} else {
		tag_len = 0;
	}

	*ciphertext_len = *plaintext_len;

	TRY(ciphertext_encrypt_decrypt(ctxt, ENCRYPT, plaintext, *plaintext_len,
				       key, key_len, iv, iv_len, aad, aad_len,
				       ciphertext, *ciphertext_len, tag,
				       tag_len));
	*ciphertext_len += tag_len;

	PRINT_ARRAY("ciphertext_2/3/4", ciphertext, *ciphertext_len);
	return ok;
}
