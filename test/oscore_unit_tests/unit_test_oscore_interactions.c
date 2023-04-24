/*
   Copyright (c) 2023 Assa Abloy. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdio.h>
#include <string.h>
#include <zephyr/ztest.h>

#include "oscore/oscore_interactions.h"

#define DUMMY_BYTE 10
#define INTERACTIONS_ARRAY_SIZE (OSCORE_INTERACTIONS_COUNT * sizeof(struct oscore_interaction_t))

#define URI_PATHS_DEFAULT "some/resource"
#define TOKEN_DEFAULT "123456"

#define URI_PATHS_2 (URI_PATHS_DEFAULT "2")
#define TOKEN_2 (TOKEN_DEFAULT "7")

static struct oscore_interaction_t default_record = 
{
	.token = TOKEN_DEFAULT,
	.token_len = sizeof(TOKEN_DEFAULT),
	.uri_paths = URI_PATHS_DEFAULT,
	.uri_paths_len = sizeof(URI_PATHS_DEFAULT),
	.request_piv = {0x01, 0x02, 0x03},
	.request_piv_len = 3,
	.request_kid = {0x10, 0x20},
	.request_kid_len = 2,
};

/**
 * @brief Call set_record and check its result.
 */
static void set_record_and_expect(struct oscore_interaction_t * interactions, struct oscore_interaction_t * record, enum err expected_result)
{
	PRINTF("set_record; expected result = %d\n", expected_result);
	enum err result = oscore_interactions_set_record(interactions, record);
	zassert_equal(expected_result, result, "");
}

/**
 * @brief Call set_record and compare resulting interactions array with expected data.
 */
static void set_record_and_compare(struct oscore_interaction_t * interactions, struct oscore_interaction_t * record, enum err expected_result, struct oscore_interaction_t * expected_interactions)
{
	set_record_and_expect(interactions, record, expected_result);
	zassert_mem_equal(interactions, expected_interactions, INTERACTIONS_ARRAY_SIZE, "");
}

/**
 * @brief Call get_record and check its result. Pointer to resulting record will be written to given handle.
 */
static void get_record_and_expect(struct oscore_interaction_t * interactions, uint8_t * token, uint8_t token_len, struct oscore_interaction_t ** record, enum err expected_result)
{
	PRINTF("get_record; expected result = %d\n", expected_result);
	enum err result = oscore_interactions_get_record(interactions, token, token_len, record);
	zassert_equal(expected_result, result, "");
}

/**
 * @brief Call get_record and compare resulting record with expected data.
 */
static void get_record_and_compare(struct oscore_interaction_t * interactions, struct oscore_interaction_t * record)
{
	struct oscore_interaction_t * received_record;
	get_record_and_expect(interactions, record->token, record->token_len, &received_record, ok);
	zassert_mem_equal(received_record, record, sizeof(struct oscore_interaction_t), "");
}

/**
 * @brief Call remove_record and check its result.
 */
static void remove_record_and_expect(struct oscore_interaction_t * interactions, uint8_t * token, uint8_t token_len, enum err expected_result)
{
	PRINTF("remove_record; expected result = %d\n", expected_result);
	enum err result = oscore_interactions_remove_record(interactions, token, token_len);
	zassert_equal(expected_result, result, "");
}

/**
 * @brief Fill given interactions array with generated records, which will be additionally stored at records_array for later checks.
 */
static void generate_and_fill(struct oscore_interaction_t * interactions, struct oscore_interaction_t * records_array)
{
	oscore_interactions_init(interactions);
	for (size_t entry = 0; entry < OSCORE_INTERACTIONS_COUNT; entry++)
	{
		struct oscore_interaction_t * record = &(records_array[entry]);
		memcpy(record, &default_record, sizeof(struct oscore_interaction_t));
		//adding one to make sure that only records other than the default one will be stored
		record->uri_paths[0] += entry + 1;
		record->token[0] += entry + 1;
		record->request_piv[0] += entry;
		record->request_kid[0] += entry;
		set_record_and_expect(interactions, record, ok);
	}
}

/**
 * @brief Test interactions array initialization.
 */
void t700_interactions_init_test(void)
{
	struct oscore_interaction_t interactions[OSCORE_INTERACTIONS_COUNT];
	struct oscore_interaction_t interactions_expected[OSCORE_INTERACTIONS_COUNT] = {0};

	/* set random data to all fields */
	memset(interactions, DUMMY_BYTE, INTERACTIONS_ARRAY_SIZE);

	enum err result = oscore_interactions_init(NULL);
	zassert_equal(wrong_parameter, result, "");

	result = oscore_interactions_init(interactions);
	zassert_equal(ok, result, "");
	zassert_mem_equal(interactions, interactions_expected, INTERACTIONS_ARRAY_SIZE, "");
}

/**
 * @brief Test setting the record into interactions array.
 */
void t701_interactions_set_record_test(void)
{
	struct oscore_interaction_t interactions[OSCORE_INTERACTIONS_COUNT];
	oscore_interactions_init(interactions);

	/* Test null pointers. */
	set_record_and_expect(NULL, NULL, wrong_parameter);
	set_record_and_expect(interactions, NULL, wrong_parameter);
	set_record_and_expect(NULL, &default_record, wrong_parameter);

	/* Test record with too big buffers. */
	struct oscore_interaction_t wrong_record = default_record;
	wrong_record.token_len = MAX_TOKEN_LEN + 1;
	set_record_and_expect(interactions, &wrong_record, wrong_parameter);

	wrong_record = default_record;
	wrong_record.uri_paths_len = OSCORE_MAX_URI_PATH_LEN + 1;
	set_record_and_expect(interactions, &wrong_record, wrong_parameter);

	wrong_record = default_record;
	wrong_record.request_piv_len = MAX_PIV_LEN + 1;
	set_record_and_expect(interactions, &wrong_record, wrong_parameter);

	wrong_record = default_record;
	wrong_record.request_kid_len = MAX_KID_LEN + 1;
	set_record_and_expect(interactions, &wrong_record, wrong_parameter);

	/* Writing record to interactions array. */
	struct oscore_interaction_t interactions_expected[OSCORE_INTERACTIONS_COUNT] = {0};
	struct oscore_interaction_t record_1 = default_record;
	interactions_expected[0] = record_1;
	interactions_expected[0].is_occupied = true;
	set_record_and_compare(interactions, &record_1, ok, interactions_expected);

	/* Writing an existing record with the same data should change nothing. */
	set_record_and_compare(interactions, &record_1, ok, interactions_expected);

	/* Writing a record with different key (URI paths), but with already used token, should fail. */
	struct oscore_interaction_t record_2 = default_record;
	memcpy(record_2.uri_paths, URI_PATHS_2, sizeof(URI_PATHS_2));
	record_2.uri_paths_len = sizeof(URI_PATHS_2);
	set_record_and_expect(interactions, &record_2, oscore_interaction_duplicated_token);

	/* Writing a record with different key (URI paths) and token should pass. */	
	memcpy(record_2.token, TOKEN_2, sizeof(TOKEN_2));
	record_2.token_len = sizeof(TOKEN_2);
	interactions_expected[1] = record_2;
	interactions_expected[1].is_occupied = true;
	set_record_and_compare(interactions, &record_2, ok, interactions_expected);

	/* Writing an existing record with changed values should change the entry accordingly. */
	record_1.request_piv[3] = 0x04;
	record_1.request_piv_len = 4;
	interactions_expected[0] = record_1;
	interactions_expected[0].is_occupied = true;
	set_record_and_compare(interactions, &record_1, ok, interactions_expected);

	/* Reset the array and fill all entries with generated records.
	   Adding another one should fail. */
	struct oscore_interaction_t generated_records[OSCORE_INTERACTIONS_COUNT];
	generate_and_fill(interactions, generated_records);
	set_record_and_expect(interactions, &default_record, oscore_max_interactions);
}

/**
 * @brief Test getting the record from interactions array.
 */
void t702_interactions_get_record_test(void)
{
	struct oscore_interaction_t interactions[OSCORE_INTERACTIONS_COUNT];
	oscore_interactions_init(interactions);

	/* Test null pointers. Null token is a valid value. */
	struct oscore_interaction_t * received_record;
	get_record_and_expect(NULL, TOKEN_DEFAULT, sizeof(TOKEN_DEFAULT), &received_record, wrong_parameter);
	get_record_and_expect(interactions, TOKEN_DEFAULT, sizeof(TOKEN_DEFAULT), NULL, wrong_parameter);

	/* Test too big token size. */
	get_record_and_expect(interactions, TOKEN_DEFAULT, MAX_TOKEN_LEN + 1, &received_record, wrong_parameter);

	/* Getting a not-stored record should fail. */
	get_record_and_expect(interactions, TOKEN_DEFAULT, sizeof(TOKEN_DEFAULT), &received_record, oscore_interaction_not_found);
	get_record_and_expect(interactions, NULL, 0, &received_record, oscore_interaction_not_found);
	get_record_and_expect(interactions, NULL, 1, &received_record, oscore_interaction_not_found);

	/* Writing a record, then getting it back should return the same data.
	   Updating a record, then getting it back should return updated data. */
	struct oscore_interaction_t record = default_record;
	set_record_and_expect(interactions, &record, ok);
	get_record_and_compare(interactions, &record);
	record.request_piv[0] += 10;
	set_record_and_expect(interactions, &record, ok);
	get_record_and_compare(interactions, &record);

	/* Reset the array and fill all entries with generated records.
	   Reading all records should pass, but reading a non-stored record should fail. */
	struct oscore_interaction_t generated_records[OSCORE_INTERACTIONS_COUNT];
	generate_and_fill(interactions, generated_records);
	for (size_t entry = 0; entry < OSCORE_INTERACTIONS_COUNT; entry++)
	{
		get_record_and_compare(interactions, &generated_records[entry]);
	}
	get_record_and_expect(interactions, default_record.token, default_record.token_len, &received_record, oscore_interaction_not_found);
}

/**
 * @brief Test removing the record from interactions array.
 */
void t703_interactions_remove_record_test(void)
{
	struct oscore_interaction_t interactions[OSCORE_INTERACTIONS_COUNT];
	oscore_interactions_init(interactions);

	/* Test null pointers. Null token is a valid value. */
	remove_record_and_expect(NULL, TOKEN_DEFAULT, sizeof(TOKEN_DEFAULT), wrong_parameter);

	/* Test too big token size. */
	remove_record_and_expect(interactions, TOKEN_DEFAULT, MAX_TOKEN_LEN + 1, wrong_parameter);

	/* Removing a not-stored record should fail. */
	remove_record_and_expect(interactions, TOKEN_DEFAULT, sizeof(TOKEN_DEFAULT), oscore_interaction_not_found);
	remove_record_and_expect(interactions, NULL, 0, oscore_interaction_not_found);
	remove_record_and_expect(interactions, NULL, 1, oscore_interaction_not_found);

	/* Adding, then removing a record should pass. */
	struct oscore_interaction_t * received_record;
	set_record_and_expect(interactions, &default_record, ok);
	get_record_and_expect(interactions, TOKEN_DEFAULT, sizeof(TOKEN_DEFAULT), &received_record, ok);
	remove_record_and_expect(interactions, TOKEN_DEFAULT, sizeof(TOKEN_DEFAULT), ok);
	get_record_and_expect(interactions, TOKEN_DEFAULT, sizeof(TOKEN_DEFAULT), &received_record, oscore_interaction_not_found);
	
	/* Reset the array and fill all entries with generated records.
	   Check if all generated records are properly stored.
	   Remove the first two records, check if they're gone.
	   Add the same two records, check if they're accessible.
	   Add another record, it should fail due to lack of free slots.
	   Check again if all generated records are properly stored. */
	struct oscore_interaction_t generated_records[OSCORE_INTERACTIONS_COUNT];
	generate_and_fill(interactions, generated_records);
	for (size_t entry = 0; entry < OSCORE_INTERACTIONS_COUNT; entry++)
	{
		get_record_and_compare(interactions, &generated_records[entry]);
	}
	remove_record_and_expect(interactions, generated_records[0].token, generated_records[0].token_len, ok);
	remove_record_and_expect(interactions, generated_records[1].token, generated_records[1].token_len, ok);
	get_record_and_expect(interactions, generated_records[0].token, generated_records[0].token_len, &received_record, oscore_interaction_not_found);
	get_record_and_expect(interactions, generated_records[1].token, generated_records[1].token_len, &received_record, oscore_interaction_not_found);
	set_record_and_expect(interactions, &generated_records[0], ok);
	set_record_and_expect(interactions, &generated_records[1], ok);
	set_record_and_expect(interactions, &default_record, oscore_max_interactions);
	for (size_t entry = 0; entry < OSCORE_INTERACTIONS_COUNT; entry++)
	{
		get_record_and_compare(interactions, &generated_records[entry]);
	}
}

/**
 * @brief Test specific usecases.
 */
void t704_interactions_usecases_test(void)
{
	struct oscore_interaction_t interactions[OSCORE_INTERACTIONS_COUNT];
	oscore_interactions_init(interactions);
	set_record_and_expect(interactions, &default_record, ok);

	// Get the record, then set it again using the same pointer (without change).
	struct oscore_interaction_t new_record_1 = default_record;
	struct oscore_interaction_t * record_1;
	get_record_and_expect(interactions, new_record_1.token, new_record_1.token_len, &record_1, ok);
	zassert_mem_equal(record_1, &default_record, sizeof(struct oscore_interaction_t), "");
	set_record_and_expect(interactions, record_1, ok); 
		/* set_record call is redundant since record_1 already points to specific entry in interactions array.
		Only called for test purposes. */

	// Get the record, then set it again using the same pointer (with change).
	struct oscore_interaction_t new_record_2 = default_record;
	struct oscore_interaction_t * record_2;
	get_record_and_expect(interactions, new_record_1.token, new_record_1.token_len, &record_1, ok);
	zassert_mem_equal(record_1, &default_record, sizeof(struct oscore_interaction_t), "");
	record_1->request_piv[0] += 1;
	new_record_2.request_piv[0] += 1;
	set_record_and_expect(interactions, record_1, ok);
		/* set_record call is redundant since record_1 already points to specific entry in interactions array.
		Only called for test purposes. */
	get_record_and_expect(interactions, new_record_2.token, new_record_2.token_len, &record_2, ok);
	zassert_mem_equal(record_2, &new_record_2, sizeof(struct oscore_interaction_t), "");
}
