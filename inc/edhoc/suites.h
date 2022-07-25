/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef SUITES_H
#define SUITES_H

#include <stdint.h>

#include "common/oscore_edhoc_error.h"

/*see https://www.iana.org/assignments/cose/cose.xhtml#algorithms for algorithm number reference*/

enum suite_label {
	SUITE_0 = 0,
	SUITE_1 = 1,
	SUITE_2 = 2,
	SUITE_3 = 3,
};

enum aead_alg {
	AES_CCM_16_64_128 = 10,
	AES_CCM_16_128_128 = 30,
};

enum hash_alg { SHA_256 = -16 };

enum ecdh_alg {
	P256 = 1,
	X25519 = 4,
};

enum sign_alg {
	ES256 = -7,
	EdDSA = -8,
};

enum mac_len {
	MAC8 = 8,
	MAC16 = 16,
};

struct suite {
	enum suite_label suite_label;
	enum aead_alg edhoc_aead;
	enum hash_alg edhoc_hash;
	enum mac_len edhoc_mac_len_static_dh;
	enum ecdh_alg edhoc_ecdh;
	enum sign_alg edhoc_sign;
	enum aead_alg app_aead;
	enum hash_alg app_hash;
};

/**
 * @brief   retrieves the algorithms coresponding to a given suite label
 * @param   label the suite label 
 * @param   suite the algorithms coresponding to label
 */
enum err get_suite(enum suite_label label, struct suite *suite);

/**
 * @brief Gets the length of the hash
 * 
 * @param alg the hash algorithm used
 * @return the length
 */
uint32_t get_hash_len(enum hash_alg alg);

/**
 * @brief Gets the length of MAC
 * 
 * @param alg the AEAD algorithm used
 * @return the length
 */
uint32_t get_aead_mac_len(enum aead_alg alg);

/**
 * @brief Gets the length of KEY
 * 
 * @param alg the AEAD algorithm used
 * @return the length
 */
uint32_t get_aead_key_len(enum aead_alg alg);

/**
 * @brief Gets the length of IV
 * 
 * @param alg the AEAD algorithm used
 * @return the length
 */
uint32_t get_aead_iv_len(enum aead_alg alg);

/**
 * @brief Gets the length of the signature
 * 
 * @param alg the signature algorithm used
 * @return the length
 */
uint32_t get_signature_len(enum sign_alg alg);

/**
 * @brief Gets the length of the ECDH public key
 * 
 * @param alg the ECDH algorithm used
 * @return the length
 */
uint32_t get_ecdh_pk_len(enum ecdh_alg alg);
#endif
