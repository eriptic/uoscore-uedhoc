/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef CIPHERTEXT_H
#define CIPHERTEXT_H
enum ciphertext { CIPHERTEXT2, CIPHERTEXT3, CIPHERTEXT4 };

/**
 * @brief 			Generates a ciphertext.
 * 
 * @param ctxt 			CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4.
 * @param suite 		Cipher suite.
 * @param[in] id_cred 		Id of the credential.
 * @param[in] signature_or_mac 	Signature or a mac byte_array.
 * @param[in] ead 		External authorization data.
 * @param[in] prk 		Pseudo random key.
 * @param[in] th 		Transcript hash.
 * @param[out] ciphertext 	The ciphertext.
 * @param[out] plaintext 	The plaintext. 
 * @return 			Ok or error code. 
 */
enum err ciphertext_gen(enum ciphertext ctxt, struct suite *suite,
			const struct byte_array *id_cred,
			struct byte_array *signature_or_mac,
			const struct byte_array *ead, struct byte_array *prk,
			struct byte_array *th, struct byte_array *ciphertext,
			struct byte_array *plaintext);

/**
 * @brief 			Decrypts a ciphertext and splits the resulting 
 * 				plaintext into its components.
 * 
 * @param ctxt 			CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4
 * @param suite 		cipher suite
 * @param[out] id_cred 		Id of the credential.
 * @param[out] signature_or_mac Signature or a mac byte_array.
 * @param[out] ead 		External authorization data.
 * @param[in] prk 		Pseudo random key.
 * @param[in] th 		Transcript hash.
 * @param[in] ciphertext 	The input.
 * @param[out] plaintext 	The plaintext.
 * @return 			Ok or error code.
 */
enum err ciphertext_decrypt_split(enum ciphertext ctxt, struct suite *suite,
				  struct byte_array *id_cred,
				  struct byte_array *sig_or_mac,
				  struct byte_array *ead,
				  struct byte_array *prk, struct byte_array *th,
				  struct byte_array *ciphertext,
				  struct byte_array *plaintext);

#endif
