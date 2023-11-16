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
 * @brief 			Xors two arrays.
 * 
 * @param[in] in1		An input array.
 * @param[in] in2 		An input array.
 * @param[out] out 		The result of the xor operation.
 * @retval			Ok or error code.
 */
static inline enum err xor_arrays(const struct byte_array *in1,
				  const struct byte_array *in2,
				  struct byte_array *out)
{
	if (in1->len != in2->len) {
		return xor_error;
	}
	for (uint32_t i = 0; i < in1->len; i++) {
		out->ptr[i] = in1->ptr[i] ^ in2->ptr[i];
	}
	return ok;
}

/**
 * @brief 			Encrypts a plaintext or decrypts a ciphertext.
 * 
 * @param ctxt 			CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4.
 * @param op 			ENCRYPT or DECRYPT.
 * @param[in] in 		Ciphertext or plaintext. 
 * @param[in] key 		The key used of encryption/decryption.
 * @param[in] nonce 		AEAD nonce.
 * @param[in] aad 		Additional authenticated data for AEAD.
 * @param[out] out 		The result.
 * @param[out] tag 		AEAD authentication tag.
 * @return 			Ok or error code. 
 */
static enum err ciphertext_encrypt_decrypt(
	enum ciphertext ctxt, enum aes_operation op,
	const struct byte_array *in, const struct byte_array *key,
	struct byte_array *nonce, const struct byte_array *aad,
	struct byte_array *out, struct byte_array *tag)
{
	if (ctxt == CIPHERTEXT2) {
		xor_arrays(in, key, out);
	} else {
		PRINT_ARRAY("in", in->ptr, in->len);
		TRY(aead(op, in, key, nonce, aad, out, tag));
	}
	return ok;
}

/**
 * @brief 			Computes the key stream for ciphertext 2 and 
 * 				the key and IV for ciphertext 3 and 4. 
 * 
 * @param ctxt 			CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4.
 * @param edhoc_hash 		The EDHOC hash algorithm.
 * @param prk 			Pseudorandom key.
 * @param th 			Transcript hash.
 * @param[out] key 		The generated key/key stream.
 * @param[out] iv 		The generated iv.
 * @return 			Ok or error code. 
 */
static enum err key_gen(enum ciphertext ctxt, enum hash_alg edhoc_hash,
			struct byte_array *prk, struct byte_array *th,
			struct byte_array *key, struct byte_array *iv)
{
	switch (ctxt) {
	case CIPHERTEXT2:
		TRY(edhoc_kdf(edhoc_hash, prk, KEYSTREAM_2, th, key));
		PRINT_ARRAY("KEYSTREAM_2", key->ptr, key->len);
		break;

	case CIPHERTEXT3:
		TRY(edhoc_kdf(edhoc_hash, prk, K_3, th, key));

		PRINT_ARRAY("K_3", key->ptr, key->len);

		TRY(edhoc_kdf(edhoc_hash, prk, IV_3, th, iv));
		PRINT_ARRAY("IV_3", iv->ptr, iv->len);
		break;

	case CIPHERTEXT4:
		PRINT_ARRAY("PRK_4e3m", prk->ptr, prk->len);
		PRINT_ARRAY("TH_4", th->ptr, th->len);
		TRY(edhoc_kdf(edhoc_hash, prk, K_4, th, key));
		PRINT_ARRAY("K_4", key->ptr, key->len);
		TRY(edhoc_kdf(edhoc_hash, prk, IV_4, th, iv));
		PRINT_ARRAY("IV_4", iv->ptr, iv->len);
		break;
	}
	return ok;
}

enum err ciphertext_decrypt_split(enum ciphertext ctxt, struct suite *suite,
				  struct byte_array *id_cred,
				  struct byte_array *sig_or_mac,
				  struct byte_array *ead,
				  struct byte_array *prk, struct byte_array *th,
				  struct byte_array *ciphertext,
				  struct byte_array *plaintext)
{
	/*generate key and iv (no iv in for ciphertext 2)*/
	uint32_t key_len;
	if (ctxt == CIPHERTEXT2) {
		key_len = ciphertext->len;
	} else {
		key_len = get_aead_key_len(suite->edhoc_aead);
	}

	BYTE_ARRAY_NEW(key, CIPHERTEXT2_SIZE, key_len);
	BYTE_ARRAY_NEW(iv, AEAD_IV_SIZE, get_aead_iv_len(suite->edhoc_aead));

	TRY(key_gen(ctxt, suite->edhoc_hash, prk, th, &key, &iv));

	/*Associated data*/
	BYTE_ARRAY_NEW(associated_data, AAD_SIZE, AAD_SIZE);
	TRY(associated_data_encode(th, &associated_data));

	PRINT_ARRAY("associated_data", associated_data.ptr,
		    associated_data.len);

	uint32_t tag_len = get_aead_mac_len(suite->edhoc_aead);
	if (ctxt != CIPHERTEXT2) {
		if (plaintext->len < tag_len) {
			return error_message_received;
		}
		plaintext->len -= tag_len;
	}
	struct byte_array tag = BYTE_ARRAY_INIT(ciphertext->ptr, tag_len);
	TRY(ciphertext_encrypt_decrypt(ctxt, DECRYPT, ciphertext, &key, &iv,
				       &associated_data, plaintext, &tag));

	PRINT_ARRAY("plaintext", plaintext->ptr, plaintext->len);

	if (ctxt == CIPHERTEXT4 && plaintext->len != 0) {
		TRY(decode_bstr(plaintext, ead));
		PRINT_ARRAY("EAD_4", ead->ptr, ead->len);
	} else if (ctxt == CIPHERTEXT4 && plaintext->len == 0) {
		ead->ptr = NULL;
		ead->len = 0;
		PRINT_MSG("No EAD_4\n");
	} else {
		TRY(plaintext_split(plaintext, id_cred, sig_or_mac, ead));
		PRINT_ARRAY("ID_CRED", id_cred->ptr, id_cred->len);
		PRINT_ARRAY("sign_or_mac", sig_or_mac->ptr, sig_or_mac->len);
		if (ead->len) {
			PRINT_ARRAY("ead", ead->ptr, ead->len);
		}
	}

	return ok;
}

enum err ciphertext_gen(enum ciphertext ctxt, struct suite *suite,
			const struct byte_array *id_cred,
			struct byte_array *signature_or_mac,
			const struct byte_array *ead, struct byte_array *prk,
			struct byte_array *th, struct byte_array *ciphertext,
			struct byte_array *plaintext)
{
	uint32_t ptxt_buf_len = plaintext->len;
	BYTE_ARRAY_NEW(signature_or_mac_enc, SIG_OR_MAC_SIZE + 2,
		       signature_or_mac->len + 2);

	TRY(encode_bstr(signature_or_mac, &signature_or_mac_enc));

	if (ctxt != CIPHERTEXT4) {
		BYTE_ARRAY_NEW(kid, KID_SIZE, KID_SIZE);
		TRY(id_cred2kid(id_cred, &kid));

		PRINT_ARRAY("kid", kid.ptr, kid.len);

		if (kid.len != 0) {
			/*id_cred_x is a KID*/
			TRY(_memcpy_s(plaintext->ptr, plaintext->len, kid.ptr,
				      kid.len));

			TRY(_memcpy_s(plaintext->ptr + kid.len,
				      plaintext->len - kid.len,
				      signature_or_mac_enc.ptr,
				      signature_or_mac_enc.len));

			plaintext->len = signature_or_mac_enc.len + kid.len;
		} else {
			/*id_cred_x is NOT a KID*/
			TRY(_memcpy_s(plaintext->ptr, plaintext->len,
				      id_cred->ptr, id_cred->len));

			TRY(_memcpy_s(plaintext->ptr + id_cred->len,
				      plaintext->len - id_cred->len,
				      signature_or_mac_enc.ptr,
				      signature_or_mac_enc.len));

			plaintext->len =
				id_cred->len + signature_or_mac_enc.len;
		}
	} else {
		plaintext->len = 0;
	}
	if (ead->len > 0) {
		TRY(_memcpy_s(plaintext->ptr + plaintext->len,
			      ptxt_buf_len - plaintext->len, ead->ptr,
			      ead->len));

		plaintext->len += ead->len;
	}

	PRINT_ARRAY("plaintext", plaintext->ptr, plaintext->len);

	/*generate key and iv (no iv in for ciphertext 2)*/
	uint32_t key_len;
	if (ctxt == CIPHERTEXT2) {
		key_len = plaintext->len;
	} else {
		key_len = get_aead_key_len(suite->edhoc_aead);
	}

	BYTE_ARRAY_NEW(key, CIPHERTEXT2_SIZE, key_len);
	BYTE_ARRAY_NEW(iv, AEAD_IV_SIZE, get_aead_iv_len(suite->edhoc_aead));

	TRY(key_gen(ctxt, suite->edhoc_hash, prk, th, &key, &iv));

	/*encrypt*/
	BYTE_ARRAY_NEW(aad, AAD_SIZE, AAD_SIZE);
	BYTE_ARRAY_NEW(tag, MAC_SIZE, get_aead_mac_len(suite->edhoc_aead));

	if (ctxt != CIPHERTEXT2) {
		/*Associated data*/
		TRY(associated_data_encode(th, &aad));
		PRINT_ARRAY("aad_data", aad.ptr, aad.len);
	} else {
		tag.len = 0;
	}

	ciphertext->len = plaintext->len;

	TRY(ciphertext_encrypt_decrypt(ctxt, ENCRYPT, plaintext, &key, &iv,
				       &aad, ciphertext, &tag));
	ciphertext->len += tag.len;

	PRINT_ARRAY("ciphertext_2/3/4", ciphertext->ptr, ciphertext->len);
	return ok;
}
