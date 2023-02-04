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
			const struct byte_array *id_cred,
			struct byte_array *signature_or_mac,
			const struct byte_array *ead, struct byte_array *prk,
			struct byte_array *th, struct byte_array *ciphertext,
			struct byte_array *plaintext);

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
				  struct byte_array *id_cred,
				  struct byte_array *sig_or_mac,
				  struct byte_array *ead,
				  struct byte_array *prk, struct byte_array *th,
				  struct byte_array *ciphertext,
				  struct byte_array *plaintext);

#endif
