/*
   Copyright (c) 2023 Assa Abloy. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdbool.h>
#include <stdint.h>
#include <string.h>

#include "oscore/oscore_interactions.h"
#include "common/byte_array.h"
#include "common/print_util.h"

#ifdef DEBUG_PRINT
static const char msg_interaction_not_found[] =
	"Couldn't find the interaction with given key.\n";
static const char msg_token_already_used[] =
	"Given token is already used by other interaction (index=%u).\n";

/**
 * @brief Print single interaction field.
 * 
 * @param msg Field name, null char included.
 * @param buffer Field buffer.
 * @param len Buffer size in bytes.
 */
static void print_interaction_field(const char *name, uint8_t *buffer,
				    uint32_t len)
{
	PRINTF("   %s: ", name);
	if (NULL != buffer) {
		for (uint32_t index = 0; index < len; index++) {
			PRINTF("%02x ", buffer[index]);
		}
	}
	PRINT_MSG("\n");
}

/**
 * @brief Print interactions array.
 * 
 * @param interactions Input interactions array.
 */
static void print_interactions(struct oscore_interaction_t *interactions)
{
	for (uint8_t index = 0; index < OSCORE_INTERACTIONS_COUNT; index++) {
		struct oscore_interaction_t *record = &interactions[index];
		PRINTF("record %02u:\n", index);
		PRINTF("   type     : %d\n", record->request_type);
		print_interaction_field("uri paths", record->uri_paths,
					record->uri_paths_len);
		print_interaction_field("token    ", record->token,
					record->token_len);
		print_interaction_field("req_piv  ", record->request_piv,
					record->request_piv_len);
		print_interaction_field("req_kid  ", record->request_kid,
					record->request_kid_len);
		PRINTF("   occupied : %s\n",
		       record->is_occupied ? "true" : "false");
	}
}

#define PRINT_INTERACTIONS(table) print_interactions(table)

#else
#define PRINT_INTERACTIONS(table)                                              \
	{                                                                      \
	}
#endif

/**
 * @brief Securely compares two memory buffers.
 * 
 * @param actual Actual value.
 * @param expected Expected value.
 * @param expected_size Number of bytes to be compared.
 * @return True if memory buffers are identical, false otherwise.
 */
static bool compare_memory(uint8_t *actual, uint32_t actual_size,
			   uint8_t *expected, uint32_t expected_size)
{
	if (actual_size != expected_size) {
		return false;
	}

	if ((NULL != actual) && (NULL != expected)) {
		return (0 == memcmp(actual, expected, expected_size));
	} else if ((NULL == actual) && (0 == expected_size)) {
		return true;
	}

	return false;
}

/**
 * @brief Searches given interactions array for a first free slot.
 * @param interactions Interactions array, MUST have exactly OSCORE_INTERACTIONS_COUNT elements.
 * @return Index of the first unoccupied slot (or OSCORE_INTERACTIONS_COUNT if the array is full).
 */
static uint32_t find_unoccupied_index(struct oscore_interaction_t *interactions)
{
	uint32_t index;
	for (index = 0; index < OSCORE_INTERACTIONS_COUNT; index++) {
		if (false == interactions[index].is_occupied) {
			break;
		}
	}
	return index;
}

/**
 * @brief Searches given interactions array for a record that matches given resource and request type.
 * @param interactions Interactions array, MUST have exactly OSCORE_INTERACTIONS_COUNT elements.
 * @param uri_paths Resource path buffer to match.
 * @param uri_paths_len Resource path buffer size.
 * @param request_type Request type to match.
 * @return Index of the record (of OSCORE_INTERACTIONS_COUNT if not found).
 */
static uint32_t
find_record_index_by_resource(struct oscore_interaction_t *interactions,
			      uint8_t *uri_paths, uint8_t uri_paths_len,
			      enum o_coap_msg request_type)
{
	uint32_t index;
	for (index = 0; index < OSCORE_INTERACTIONS_COUNT; index++) {
		bool is_occupied = interactions[index].is_occupied;
		bool request_type_ok =
			(interactions[index].request_type == request_type);
		bool uri_path_ok =
			compare_memory(uri_paths, uri_paths_len,
				       interactions[index].uri_paths,
				       interactions[index].uri_paths_len);
		if (is_occupied && request_type_ok && uri_path_ok) {
			break;
		}
	}
	return index;
}

/**
 * @brief Searches given interactions array for a record that matches given token.
 * @param interactions Interactions array, MUST have exactly OSCORE_INTERACTIONS_COUNT elements.
 * @param token Token buffer to match.
 * @param token_len Token buffer size.
 * @return Index of the record (if found), or OSCORE_INTERACTIONS_COUNT (if not found).
 */
static uint32_t
find_record_index_by_token(struct oscore_interaction_t *interactions,
			   uint8_t *token, uint8_t token_len)
{
	uint32_t index;
	for (index = 0; index < OSCORE_INTERACTIONS_COUNT; index++) {
		bool is_occupied = interactions[index].is_occupied;
		bool token_ok = compare_memory(token, token_len,
					       interactions[index].token,
					       interactions[index].token_len);
		if (is_occupied && token_ok) {
			break;
		}
	}
	return index;
}

enum err oscore_interactions_init(struct oscore_interaction_t *interactions)
{
	if (NULL == interactions) {
		return wrong_parameter;
	}

	memset(interactions, 0,
	       sizeof(struct oscore_interaction_t) * OSCORE_INTERACTIONS_COUNT);
	return ok;
}

enum err
oscore_interactions_set_record(struct oscore_interaction_t *interactions,
			       struct oscore_interaction_t *record)
{
	if ((NULL == interactions) || (NULL == record) ||
	    (record->token_len > MAX_TOKEN_LEN) ||
	    (record->uri_paths_len > OSCORE_MAX_URI_PATH_LEN) ||
	    (record->request_piv_len > MAX_PIV_LEN) ||
	    (record->request_kid_len > MAX_KID_LEN)) {
		return wrong_parameter;
	}

	// Find the entry at which the record will be stored.
	uint32_t index_by_uri =
		find_record_index_by_resource(interactions, record->uri_paths,
					      record->uri_paths_len,
					      record->request_type);
	if (index_by_uri >= OSCORE_INTERACTIONS_COUNT) {
		index_by_uri = find_unoccupied_index(interactions);
		if (index_by_uri >= OSCORE_INTERACTIONS_COUNT) {
			return oscore_max_interactions;
		}
	}

	// Prevent from using the same token twice, as it would be impossible to find the proper record with get_record.
	uint32_t index_by_token = find_record_index_by_token(
		interactions, record->token, record->token_len);
	if ((index_by_token < OSCORE_INTERACTIONS_COUNT) &&
	    (index_by_token != index_by_uri)) {
		PRINTF(msg_token_already_used, index_by_token);
		return oscore_interaction_duplicated_token;
	}

	record->is_occupied = true;

	// Memmove is used to avoid overlapping issues when get_record output is used as the record.
	memmove(&interactions[index_by_uri], record, sizeof(*record));
	PRINT_MSG("set record:\n");
	PRINT_INTERACTIONS(interactions);
	return ok;
}

enum err
oscore_interactions_get_record(struct oscore_interaction_t *interactions,
			       uint8_t *token, uint8_t token_len,
			       struct oscore_interaction_t **record)
{
	if ((NULL == interactions) || (NULL == record) ||
	    (token_len > MAX_TOKEN_LEN)) {
		return wrong_parameter;
	}
	*record = NULL;

	PRINT_MSG("get record:\n");
	PRINT_INTERACTIONS(interactions);

	uint32_t index =
		find_record_index_by_token(interactions, token, token_len);
	if (index >= OSCORE_INTERACTIONS_COUNT) {
		PRINT_MSG(msg_interaction_not_found);
		PRINT_ARRAY("token", token, token_len);
		return oscore_interaction_not_found;
	}

	*record = &interactions[index];
	return ok;
}

enum err
oscore_interactions_remove_record(struct oscore_interaction_t *interactions,
				  uint8_t *token, uint8_t token_len)
{
	if ((NULL == interactions) || (token_len > MAX_TOKEN_LEN)) {
		return wrong_parameter;
	}

	PRINT_MSG("remove record (before):\n");
	PRINT_INTERACTIONS(interactions);

	uint32_t index =
		find_record_index_by_token(interactions, token, token_len);
	if (index >= OSCORE_INTERACTIONS_COUNT) {
		PRINT_MSG(msg_interaction_not_found);
		PRINT_ARRAY("token", token, token_len);
		return oscore_interaction_not_found;
	}

	memset(&interactions[index], 0, sizeof(struct oscore_interaction_t));
	PRINT_MSG("remove record (after):\n");
	PRINT_INTERACTIONS(interactions);
	return ok;
}

enum err oscore_interactions_read_wrapper(
	enum o_coap_msg msg_type, struct byte_array *token,
	struct oscore_interaction_t *interactions,
	struct byte_array *request_piv, struct byte_array *request_kid)
{
	if ((NULL == token) || (NULL == interactions) ||
	    (NULL == request_piv) || (NULL == request_kid)) {
		return wrong_parameter;
	}

	if ((COAP_MSG_RESPONSE == msg_type) ||
	    (COAP_MSG_NOTIFICATION == msg_type)) {
		/* Server sends / Client receives any response (notification included) - read the record from interactions array and update request_piv and request_kid. */
		struct oscore_interaction_t *record;
		TRY(oscore_interactions_get_record(interactions, token->ptr,
						   (uint8_t)token->len,
						   &record));
		request_piv->ptr = record->request_piv;
		request_piv->len = record->request_piv_len;
		request_kid->ptr = record->request_kid;
		request_kid->len = record->request_kid_len;
	}

	return ok;
}

enum err oscore_interactions_update_wrapper(
	enum o_coap_msg msg_type, struct byte_array *token,
	struct byte_array *uri_paths, struct oscore_interaction_t *interactions,
	struct byte_array *request_piv, struct byte_array *request_kid)
{
	if ((NULL == token) || (NULL == uri_paths) || (NULL == interactions) ||
	    (NULL == request_piv) || (NULL == request_kid)) {
		return wrong_parameter;
	}

	// cancellation must be interpreted as a registration, to properly match the corresponding record from the interactions table.
	if (COAP_MSG_CANCELLATION == msg_type) {
		msg_type = COAP_MSG_REGISTRATION;
	}

	if ((COAP_MSG_REQUEST == msg_type) ||
	    (COAP_MSG_REGISTRATION == msg_type)) {
		/* Server receives / client sends any request (including registration and cancellation) - add the record to the interactions array.
		   Request_piv and request_kid not updated - current values of PIV and KID (Sender ID) are used. */
		struct oscore_interaction_t record = {
			.request_piv_len = (uint8_t)request_piv->len,
			.request_kid_len = (uint8_t)request_kid->len,
			.token_len = (uint8_t)token->len,
			.uri_paths_len = (uint8_t)uri_paths->len,
			.request_type = msg_type
		};
		TRY(_memcpy_s(record.request_piv, MAX_PIV_LEN, request_piv->ptr,
			      request_piv->len));
		TRY(_memcpy_s(record.request_kid, MAX_KID_LEN, request_kid->ptr,
			      request_kid->len));
		TRY(_memcpy_s(record.token, MAX_TOKEN_LEN, token->ptr,
			      token->len));
		TRY(_memcpy_s(record.uri_paths, OSCORE_MAX_URI_PATH_LEN,
			      uri_paths->ptr, uri_paths->len));
		TRY(oscore_interactions_set_record(interactions, &record));
	} else if (COAP_MSG_RESPONSE == msg_type) {
		/* Server sends / client receives a regular response - remove the record. */
		//TODO removing records must be taken into account when No-Response support will be added.
		TRY(oscore_interactions_remove_record(interactions, token->ptr,
						      (uint8_t)token->len));
	}

	return ok;
}
