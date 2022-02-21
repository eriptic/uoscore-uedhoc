/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef SIGNATURE_OR_MAC_MSG_H
#define SIGNATURE_OR_MAC_MSG_H

#include <stdbool.h>

#include "suites.h"

#include "common/oscore_edhoc_error.h"

enum sgn_or_mac_op { VERIFY, GENERATE };

/**
 * @brief   Encodes an array of data to cbor byte string
 * @param   in pointer to data to be encoded
 * @param   in_len length of in
 * @param   out pointer to the output buffer
 * @param   out_len length of out
 * @retval  edhoc error code
 */
enum err encode_byte_string(const uint8_t *in, uint32_t in_len, uint8_t *out,
			    uint32_t *out_len);

enum err decode_byte_string(const uint8_t *in, const uint32_t in_len,
			    uint8_t *out, uint32_t *out_len);

/**
 * @brief   If the calling party (initiator / responder) authenticates with 
 *          static DH keys it calculates the MAC. Otherwise it calculates a 
 *          message to be signed.
 * @param   static_dh_auth true if the caller of this fuction authenticates 
 *          with static DH keys
 * @param   suite the cipher suite used
 * @param   label_k label to be used in the key derivation
 * @param   label_iv label to be used in the iv derivation
 * @param   prk pseudo random key to be used in key iv derivation 
 * @param   prk_len length of prk
 * @param   th transcript hash
 * @param   th_len length of th
 * @param   id_cred ID_CRED of the calling party
 * @param   id_cred_len length of id_cred
 * @param   cred CRED of the calling party
 * @param   cred_len length of cred
 * @param   ad aditionall data
 * @param   ad_len length of ad
 * @param   m message to be signed
 * @param   m_len length of m
 * @param   mac MAC_2/MAC_3 when the calling party uses static DH authentication
 * @param   m_len length of mac
 */
enum err signature_or_mac_msg_create(
	bool static_dh_auth, struct suite suite, const char *label_k,
	const char *label_iv, const uint8_t *prk, const uint8_t prk_len,
	const uint8_t *th, const uint8_t th_len, const uint8_t *id_cred,
	const uint8_t id_cred_len, const uint8_t *cred, const uint16_t cred_len,
	const uint8_t *ad, const uint8_t ad_len, uint8_t *m, uint16_t *m_len,
	uint8_t *mac, uint8_t *mac_len);

enum err mac(const uint8_t *prk, uint32_t prk_len, const uint8_t *th,
	     uint32_t th_len, const uint8_t *id_cred, uint32_t id_cred_len,
	     const uint8_t *cred, uint32_t cred_len, const uint8_t *ead,
	     uint32_t ead_len, const char *mac_label, bool static_dh,
	     struct suite *suite, uint8_t *mac, uint32_t *mac_len);

enum err
signature_or_mac(enum sgn_or_mac_op op, bool static_dh, struct suite *suite,
		 const uint8_t *sk, uint32_t sk_len, const uint8_t *pk,
		 uint32_t pk_len, const uint8_t *prk, uint32_t prk_len,
		 const uint8_t *th, uint32_t th_len, const uint8_t *id_cred,
		 uint32_t id_cred_len, const uint8_t *cred, uint32_t cred_len,
		 const uint8_t *ead, uint32_t ead_len, const char *mac_label,
		 uint8_t *signature_or_mac, uint32_t *signature_or_mac_len);

#endif
