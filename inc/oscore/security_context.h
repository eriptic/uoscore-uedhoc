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
#include "oscore/replay_protection.h"
#include "oscore/oscore_interactions.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/* Upper limit of SSN that is allowed by AEAD algorithm (AES-CCM-16-64-128) is 2^23-1, according to RFC 9053 p. 4.2.1.
   Exceeding this value results in constant 4.01 Unauthorized error, so new security context must be established.
   Note that this value is lower than MAX_PIV_FIELD_VALUE, which only defines maximum value that is writable to the SSN/PIV field.
*/
#ifndef OSCORE_SSN_OVERFLOW_VALUE
#define OSCORE_SSN_OVERFLOW_VALUE 0x7FFFFF
#endif

enum derive_type {
	KEY,
	IV,
};

/**
 * @brief State machine for replay window synchronization using ECHO option after server reboot.
 */
enum echo_state {
	ECHO_REBOOT, /* default value after reboot */
	ECHO_VERIFY, /* verification in progress */
	ECHO_SYNCHRONIZED, /* synchronized, normal operation */
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
	uint64_t ssn;
};

/* Recipient Context used to decrypt inbound messages */
struct recipient_context {
	struct byte_array recipient_id;
	struct byte_array recipient_key;
	uint8_t recipient_key_buf[RECIPIENT_KEY_LEN_];
	uint8_t recipient_id_buf[RECIPIENT_ID_BUFF_LEN];
	struct server_replay_window_t replay_window;
	uint64_t notification_num;
	bool notification_num_initialized; /* this is only used to skip the first notification check after the reboot */
};

/*request-response context contains parameters that need to persists between
 * requests and responses*/
struct req_resp_context {
	struct byte_array nonce;
	uint8_t nonce_buf[NONCE_LEN];

	struct oscore_interaction_t interactions[OSCORE_INTERACTIONS_COUNT];

	struct byte_array echo_opt_val;
	uint8_t echo_opt_val_buf[ECHO_OPT_VALUE_LEN];

	enum echo_state echo_state_machine;
};

/* Context struct containing all contexts*/
struct context {
	struct req_resp_context rrc;
	struct common_context cc;
	struct sender_context sc;
	struct recipient_context rc;
};

/**
 * @brief   Converts the sender sequence number (uint64_t) to 
 *          piv (byte string of maximum 5 byte) 
 * @param   ssn the sender sequence number
 * @param   piv Partial IV
 */
enum err ssn2piv(uint64_t ssn, struct byte_array *piv);

/**
 * @brief Converts PIV (byte string of maximum 5 bytes) to 
 *        Sender Sequence Number (uint64_t)
 * @param piv Partial IV
 * @param ssn Sender Sequence Number
 */
enum err piv2ssn(struct byte_array *piv, uint64_t *ssn);

/**
 * @brief	Updates the request_piv and the request_kid
 * @param	c the context
 * @param	piv	the new PIV
 * @param 	kid the new KID
 * @retval 	error code
*/
enum err update_request_piv_request_kid(struct context *c,
					struct byte_array *piv,
					struct byte_array *kid);

/**
 * @brief Check if given security context is still safe to be used, or a new one must be established.
 *        For more info, refer to RFC 8613 p. 7.2.1.
 * @param c security context.
 * @return enum err 
 */
enum err check_context_freshness(struct context *c);
#endif
