/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef SECURITY_CONTEXT_H
#define SECURITY_CONTEXT_H

#include "supported_algorithm.h"
#include "oscore_coap.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

#define REPLAY_WINDOW_LEN 32

enum dev_type {
	SERVER,
	CLIENT,
};

enum derive_type {
	KEY,
	IV,
};

/**
 * @brief Common Context
 * Contains information common to the Sender and Recipient Contexts
 */
struct common_context {
	enum AEAD_algorithm aead_alg;
	enum hkdf kdf;
	struct byte_array master_secret;
	struct byte_array master_salt; /*optional*/
	struct byte_array id_context; /*optional*/
	struct byte_array common_iv;
	uint8_t common_iv_buf[COMMON_IV_LEN];
};

/* Sender Context used for encrypting outbound messages */
struct sender_context {
	struct byte_array sender_id;
	uint8_t sender_id_buf[7];
	struct byte_array sender_key;
	uint8_t sender_key_buf[SENDER_KEY_LEN_];
	uint64_t sender_seq_num;
};

/* Recipient Context used to decrypt inbound messages */
struct recipient_context {
	struct byte_array recipient_id;
	struct byte_array recipient_key;
	uint8_t recipient_key_buf[RECIPIENT_KEY_LEN_];
	uint64_t replay_window[REPLAY_WINDOW_LEN];
	uint8_t replay_window_len;
};

/*request-response context contains parameters that need to persists between
 * requests and responses*/
struct req_resp_context {
	struct byte_array nonce;
	uint8_t nonce_buf[NONCE_LEN];

	struct byte_array aad;
	uint8_t aad_buf[MAX_AAD_LEN];

	struct byte_array piv;
	uint8_t piv_buf[MAX_PIV_LEN];

	struct byte_array kid_context;
	uint8_t kid_context_buf[MAX_KID_CONTEXT_LEN];

	struct byte_array kid;
	uint8_t kid_buf[MAX_KID_LEN];
};

/* Context struct containing all contexts*/
struct context {
	struct req_resp_context rrc;
	struct common_context cc;
	struct sender_context sc;
	struct recipient_context rc;
};

/**
 * @brief   converts the sender sequence number (uint64_t) to 
 *          piv (byte string of maximum 5 byte) 
 * @param   ssn the sender sequence number
 * @param   piv Partial IV
 */
enum err sender_seq_num2piv(uint64_t ssn, struct byte_array *piv);

/**
 * @brief   Updates runtime parameter of the context
 * @param   type of the device SERVER/CLIENT
 * @param   options pointer to an array of options
 * @param   opt_num number of options
 * @param   new_piv new PIV
 * @param   new_kid_context 
 * @param   c oscore context
 */
enum err context_update(enum dev_type dev, struct o_coap_option *options,
			uint16_t opt_num, struct byte_array *new_piv,
			struct byte_array *new_kid_context, struct context *c);

#endif
