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
 * @brief Generates a ciphertext
 * 
 * @param ctxt CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4
 * @param suite cipher suite
 * @param id_cred ID_CRED
 * @param id_cred_len lenhgt of ID_CRED
 * @param signature_or_mac buffer containing signature or a mac
 * @param signature_or_mac_len lenhgt of signature_or_mac
 * @param ead additional authenticated data
 * @param ead_len lenhgt of ead
 * @param prk pseudo random key
 * @param prk_len lenhgt of prk
 * @param th transkript hash
 * @param th_len lenhgt of th
 * @param plaintext a plaintext constructed from the other input parameters
 * @param plaintext_len length of plaintext
 * @param ciphertext the output
 * @param ciphertext_len lenhgt of the output
 * @return enum err 
 */
enum err ciphertext_gen(enum ciphertext ctxt, struct suite *suite,
			uint8_t *id_cred, uint32_t id_cred_len,
			uint8_t *signature_or_mac,
			uint32_t signature_or_mac_len, uint8_t *ead,
			uint32_t ead_len, uint8_t *prk, uint32_t prk_len,
			uint8_t *th, uint32_t th_len, uint8_t *ciphertext,
			uint32_t *ciphertext_len, uint8_t *plaintext,
			uint32_t *plaintext_len);

/**
 * @brief Decrypts a ciphertest and splits the resulting plaintext into its 
 *        components.
 * 
 * @param ctxt CIPHERTEXT2, CIPHERTEXT3 or CIPHERTEXT4
 * @param suite cipher suite
 * @param id_cred ID_CRED
 * @param id_cred_len lenhgt of ID_CRED
 * @param signature_or_mac buffer containing signature or a mac
 * @param signature_or_mac_len lenhgt of signature_or_mac
 * @param ead additional authenticated data
 * @param ead_len lenhgt of ead
 * @param prk pseudo random key
 * @param prk_len lenhgt of prk
 * @param th transkript hash
 * @param th_len lenhgt of th
 * @param ciphertext the input
 * @param ciphertext_len lenhgt of the input
 * @param plaintext the plaintext
 * @param plaintext_len the length of the plaintext
 * @return enum err 
 */
enum err ciphertext_decrypt_split(enum ciphertext ctxt, struct suite *suite,
				  uint8_t *id_cred, uint32_t *id_cred_len,
				  uint8_t *signature_or_mac,
				  uint32_t *signature_or_mac_len, uint8_t *ead,
				  uint32_t *ead_len, uint8_t *prk,
				  uint32_t prk_len, uint8_t *th,
				  uint32_t th_len, uint8_t *ciphertext,
				  uint32_t ciphertext_len, uint8_t *plaintext,
				  uint32_t plaintext_len);

#endif
