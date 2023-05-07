/*
   Copyright (c) 2023 Assa Abloy. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef OSCORE_INTERACTIONS_H
#define OSCORE_INTERACTIONS_H

#include <stdint.h>
#include "oscore/oscore_coap_defines.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief Number of interactions supported at the same time, per one OSCORE context.
 */
#ifndef OSCORE_INTERACTIONS_COUNT
#define OSCORE_INTERACTIONS_COUNT 3
#endif

/**
 * @brief Single record of interaction between the server and the client.
 */
struct oscore_interaction_t {
	/* Request type, used to distinguish between normal request and resource observations. */
	enum o_coap_msg request_type;

	/* CoAP token of the subscription request. */
	uint8_t token[MAX_TOKEN_LEN];
	uint8_t token_len;

	/* Full URI path (all options concatenated to single string). */
	uint8_t uri_paths[OSCORE_MAX_URI_PATH_LEN];
	uint8_t uri_paths_len;

	/* PIV of the subscription request. */
	uint8_t request_piv[MAX_PIV_LEN];
	uint8_t request_piv_len;

	/* KID of the subscription request. */
	uint8_t request_kid[MAX_KID_LEN];
	uint8_t request_kid_len;

	/* True if given record is occupied (used in interactions array). */
	bool is_occupied;
};

/**
 * @brief Initialize interactions array.
 * 
 * @param interactions Interactions array, MUST have exactly OSCORE_INTERACTIONS_COUNT elements.
 * @return enum err ok, or error if failed.
 */
enum err oscore_interactions_init(struct oscore_interaction_t *interactions);

/**
 * @brief Add new record to the interactions array, or replace the old one if it exists (URI paths field is used for comparison).
 * @note To be used while registering to given resource.
 * @param interactions Interactions array, MUST have exactly OSCORE_INTERACTIONS_COUNT elements.
 * @param record Single record to be added or updated.
 * @return enum err ok, or error if failed.
 */
enum err
oscore_interactions_set_record(struct oscore_interaction_t *interactions,
			       struct oscore_interaction_t *record);

/**
 * @brief Search for the record matching given token and return a pointer to it.
 * @note To be used while encrypting a notification on the server side, and confirming its AAD on the client side.
 * @param interactions Interactions array, MUST have exactly OSCORE_INTERACTIONS_COUNT elements.
 * @param token Token buffer to match.
 * @param token_len Token buffer size.
 * @param record [out] Pointer to the matching record.
 * @return enum err ok, or error if failed.
 */
enum err
oscore_interactions_get_record(struct oscore_interaction_t *interactions,
			       uint8_t *token, uint8_t token_len,
			       struct oscore_interaction_t **record);

/**
 * @brief Remove a record that matches given URI paths field.
 * @note To be used while de-registering to given resource.
 * @param interactions Interactions array, MUST have exactly OSCORE_INTERACTIONS_COUNT elements.
 * @param token Token buffer to match.
 * @param token_len Token buffer size.
 * @return enum err ok, or error if failed.
 */
enum err
oscore_interactions_remove_record(struct oscore_interaction_t *interactions,
				  uint8_t *token, uint8_t token_len);

/**
 * @brief Wrapper for handling OSCORE interactions to be executed before main encryption/decryption logic.
 * 
 * @param msg_type Message type of the packet.
 * @param token Token byte array. MUST NOT be NULL, but can be empty.
 * @param interactions Interactions array, MUST have exactly OSCORE_INTERACTIONS_COUNT elements.
 * @param request_piv Output request_piv (to be updated if needed).
 * @param request_kid Output request_kid (to be updated if needed).
 * @return enum err ok, or error if failed.
 */
enum err oscore_interactions_read_wrapper(
	enum o_coap_msg msg_type, struct byte_array *token,
	struct oscore_interaction_t *interactions,
	struct byte_array *request_piv, struct byte_array *request_kid);

/**
 * @brief Wrapper for handling OSCORE interactions to be executed after main encryption/decryption logic.
 * 
 * @param msg_type Message type of the packet.
 * @param token Token byte array. MUST NOT be NULL, but can be empty.
 * @param uri_paths URI Paths byte array. MUST NOT be null, but can be empty.
 * @param interactions Interactions array, MUST have exactly OSCORE_INTERACTIONS_COUNT elements.
 * @param request_piv Current value of request_piv.
 * @param request_kid Current value of request_kid.
 * @return enum err ok, or error if failed.
 */
enum err oscore_interactions_update_wrapper(
	enum o_coap_msg msg_type, struct byte_array *token,
	struct byte_array *uri_paths, struct oscore_interaction_t *interactions,
	struct byte_array *request_piv, struct byte_array *request_kid);

#endif
