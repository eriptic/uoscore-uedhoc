/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef CRYPTO_WRAPPER_H
#define CRYPTO_WRAPPER_H

#include "byte_array.h"
#include "oscore_edhoc_error.h"

#include "edhoc/suites.h"

/*Indicates what kind of operation a symmetric cipher will execute*/
enum aes_operation {
	ENCRYPT,
	DECRYPT,
};

/**
 * @brief   Calculates AEAD encryption decryption
 * @param   op opeartion to be executed (ENCRYPT or DECRYPT)
 * @param   in  input message
 * @param   in_len length of in
 * @param   key the symmetric key to be used
 * @param   key_len length of key
 * @param   nonce the nonce
 * @param   nonce_len length of nonce
 * @param   aad additional authenticated data
 * @param   aad_len length of add
 * @param   out the cipher text
 * @param   out_len the length of out
 * @param   tag the authentication tag
 * @param   tag_len the length of tag
 * @retval  an err code
 */
enum err aead(enum aes_operation op, const uint8_t *in, const uint32_t in_len,
	      const uint8_t *key, const uint32_t key_len, uint8_t *nonce,
	      const uint32_t nonce_len, const uint8_t *aad,
	      const uint32_t aad_len, uint8_t *out, const uint32_t out_len,
	      uint8_t *tag, const uint32_t tag_len);

/**
 * @brief   Derives ECDH shared secret
 * @param   alg the ECDH algorithm
 * @param   sk private key
 * @param   sk_len length of sk
 * @param   pk public key
 * @param   pk_len length of pk
 * @param   shared_secret the result
 * @retval  an err code
 */
enum err shared_secret_derive(enum ecdh_alg alg, const uint8_t *sk,
			      const uint32_t sk_len, const uint8_t *pk,
			      const uint32_t pk_len, uint8_t *shared_secret);

/**
 * @brief   HKDF extract function, see rfc5869
 * @param   alg hash algorithm to be used
 * @param   salt salt value
 * @param   salt_len length of salt
 * @param   ikm input keying material
 * @param   ikm_len length of ikm
 * @param   out result
 * @retval  an err code
 */
enum err hkdf_extract(enum hash_alg alg, const uint8_t *salt, uint32_t salt_len,
		      uint8_t *ikm, uint32_t ikm_len, uint8_t *out);

/**
 * @brief   HKDF expand function, see rfc5869
 * @param   alg hash algorithm to be used
 * @param   prk input pseudo random key
 * @param   prk_len length of prk
 * @param   info info input parameter
 * @param   info_len length of info
 * @param   out the result
 * @param   out_len length of out
 * @retval  an err code
 */
enum err hkdf_expand(enum hash_alg alg, const uint8_t *prk,
		     const uint32_t prk_len, const uint8_t *info,
		     const uint32_t info_len, uint8_t *out, uint32_t out_len);

/**
 * @brief   calculates a hash
 * @param   alg the hash algorithm
 * @param   in input message
 * @param   in_len length of in
 * @param   out the hash 
 * @retval  an err code
 */
enum err hash(enum hash_alg alg, const uint8_t *in, const uint32_t in_len,
	      uint8_t *out);

/**
 * @brief   Verifies an asymmetric signature
 * @param   alg signature algorithm to be used
 * @param   sk secret key
 * @param   sk_len length of sk
 * @param   pk public key
 * @param   msg the message to be signed
 * @param   msg_len length of msg
 * @param   out signature
 * @retval  an err code
 */
enum err sign(enum sign_alg alg, const uint8_t *sk, const uint32_t sk_len,
	      const uint8_t *pk, const uint8_t *msg, const uint32_t msg_len,
	      uint8_t *out);

/**
 * @brief   Verifies an asymmetric signature
 * @param   alg signature algorithm to be used
 * @param   pk public key
 * @param   pk_len length of pk
 * @param   msg the signed message
 * @param   msg_len length of msg
 * @param   sgn signature
 * @param   sgn_len length of sgn
 * @param   result true if the signature verification is successfully
 * @retval  an err code
 */
enum err verify(enum sign_alg alg, const uint8_t *pk, const uint32_t pk_len,
		const uint8_t *msg, const uint32_t msg_len, const uint8_t *sgn,
		const uint32_t sgn_len, bool *result);

/**
 * @brief   HKDF funcion used for the derivation of the Common IV, 
 *          Recipient/Sender keys.
 * @param   master_secret the master secret
 * @param   master_salt the master salt
 * @param   info a CBOR structure containing id, id_context, alg_aead, type, L 
 * @param   out the derived Common IV, Recipient/Sender keys
 */
enum err hkdf_sha_256(struct byte_array *master_secret,
		      struct byte_array *master_salt, struct byte_array *info,
		      struct byte_array *out);

#endif
