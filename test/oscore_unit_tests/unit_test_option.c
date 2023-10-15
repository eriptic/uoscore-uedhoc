/*
   Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <string.h>

#include "oscore/option.h"
#include "common/byte_array.h"

#define GET_ARRAY_SIZE(_array) (sizeof(_array) / sizeof(_array[0]))

static void uri_path_create_and_expect(struct o_coap_option *options, uint32_t options_size, uint8_t * uri_path, uint32_t * uri_path_size, enum err expected_result)
{
	PRINTF("uri_path_create; expected result = %d\n", expected_result);
	enum err result = uri_path_create(options, options_size, uri_path, uri_path_size);
	zassert_equal(expected_result, result, "unexpected result: %d", result);
}

static void uri_path_create_and_compare(struct o_coap_option *options, uint32_t options_size, uint8_t * uri_path, uint32_t * uri_path_size, enum err expected_result, uint8_t * expected_uri_path, uint32_t expected_uri_path_size)
{
	uri_path_create_and_expect(options, options_size, uri_path, uri_path_size, expected_result);
	zassert_equal(expected_uri_path_size, *uri_path_size, "unexpected output size: %d", *uri_path_size);
	zassert_mem_equal(expected_uri_path, uri_path, expected_uri_path_size, "");
	*uri_path_size = OSCORE_MAX_URI_PATH_LEN; //restore valid buffer size (cleanup for next calls).
}

static void get_observe_value_and_compare(struct o_coap_option *options, uint8_t options_cnt, struct byte_array * output, bool expected_result, struct byte_array * expected_output)
{
	PRINTF("get_observe_value; expected result = %d\n", expected_result);
	bool result = get_observe_value(options, options_cnt, output);
	zassert_equal(expected_result, result, "unexpected result: %d", result);

	if (NULL != expected_output)
	{
		zassert_equal(true, array_equals(output, expected_output), "");
	}
}

void t400_is_class_e(void)
{
	enum o_num not_e_opt_nums[] = { URI_HOST, URI_PORT, OSCORE, PROXY_URI,
					PROXY_SCHEME };

	uint32_t len = sizeof(not_e_opt_nums) / sizeof(not_e_opt_nums[0]);
	for (uint32_t i = 0; i < len; i++) {
		zassert_equal(is_class_e(not_e_opt_nums[i]), false, "");
	}
}

void t401_cache_echo_val(void)
{
	struct byte_array empty = BYTE_ARRAY_INIT(NULL, 0);
	enum err r;

	struct o_coap_option options[] = {
		{ .delta = 2, .len = 0, .value = NULL, .option_number = 2 },
		{ .delta = 2, .len = 0, .value = NULL, .option_number = 4 },
		{ .delta = 3, .len = 0, .value = NULL, .option_number = 7 },
		{ .delta = 5, .len = 0, .value = NULL, .option_number = ECHO }
	};

	/*successful caching*/
	r = cache_echo_val(&empty, (struct o_coap_option *)&options, 4);
	zassert_equal(r, ok, "Error in cache_echo_val. r: %d", r);

	/*unsuccessful caching */
	r = cache_echo_val(&empty, (struct o_coap_option *)&options, 3);
	zassert_equal(r, no_echo_option, "Error in cache_echo_val. r: %d", r);
}

void t402_echo_val_is_fresh(void)
{
	enum err r;

	uint8_t cache_val_buf[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
				    0x06, 0x07, 0x08, 0x09, 0x10, 0x11 };

	struct byte_array cache_val =
		BYTE_ARRAY_INIT(cache_val_buf, sizeof(cache_val_buf));

	uint8_t decrypted_payload_buf[] = { 0x01 }; /*code only*/
	struct byte_array decrypted_payload = BYTE_ARRAY_INIT(
		decrypted_payload_buf, sizeof(decrypted_payload_buf));

	/*test no ECHO option*/
	r = echo_val_is_fresh(&cache_val, &decrypted_payload);
	zassert_equal(r, no_echo_option, "Error in echo_val_is_fresh. r: %d",
		      r);

	/*test ECHO option mismatch*/
	uint8_t decrypted_payload_buf_mismatch[] = {
		0x81, 0xDC, 0xEF, 0x00, 0x01, 0x02, 0x03, 0x04,
		0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x12
	}; /*wrong last byte of the ECHO option*/
	struct byte_array decrypted_payload_mismatch =
		BYTE_ARRAY_INIT(decrypted_payload_buf_mismatch,
				sizeof(decrypted_payload_buf_mismatch));

	r = echo_val_is_fresh(&cache_val, &decrypted_payload_mismatch);
	zassert_equal(r, echo_val_mismatch, "Error in echo_val_is_fresh. r: %d",
		      r);
}

void t403_uri_path_create(void)
{
	struct o_coap_option default_options[] = {
		{ .option_number = IF_NONE_MATCH },
		{ .option_number = URI_PATH, .value = "path", .len = 4 },
		{ .option_number = URI_PATH, .value = "to", .len = 2 },
		{ .option_number = OSCORE },
		{ .option_number = URI_PATH, .value = "rsc", .len = 3 },
	};
	uint32_t default_size = GET_ARRAY_SIZE(default_options);
	uint8_t expected_default_path[] = "path/to/rsc";
	
	uint8_t output_buffer[OSCORE_MAX_URI_PATH_LEN];
	uint32_t output_buffer_size = sizeof(output_buffer);

	/* Test null pointers. */
	uri_path_create_and_expect(NULL, default_size, output_buffer, &output_buffer_size, wrong_parameter);
	uri_path_create_and_expect(default_options, default_size, NULL, &output_buffer_size, wrong_parameter);
	uri_path_create_and_expect(default_options, default_size, output_buffer, NULL, wrong_parameter);

	/* Test too small output buffer. */
	uint32_t wrong_output_size = 2; //should fail while adding first element
	uri_path_create_and_expect(default_options, default_size, output_buffer, &wrong_output_size, buffer_to_small);
	wrong_output_size = 4; //should fail while adding '/' after first element
	uri_path_create_and_expect(default_options, default_size, output_buffer, &wrong_output_size, buffer_to_small);
	wrong_output_size = 10; //should fail while adding last element
	uri_path_create_and_expect(default_options, default_size, output_buffer, &wrong_output_size, buffer_to_small);

	/* Wrong option should fail. */
	struct o_coap_option wrong_option[] = {
		{ .option_number = MAX_AGE },
		{ .option_number = URI_PATH, .value = "path", .len = 4 },
		{ .option_number = URI_PATH, .value = NULL, .len = 2 },
		{ .option_number = OSCORE },
		{ .option_number = URI_PATH, .value = "rsc", .len = 3 },
	};
	uint32_t wrong_size = GET_ARRAY_SIZE(wrong_option);
	uri_path_create_and_expect(wrong_option, wrong_size, output_buffer, &output_buffer_size, oscore_wrong_uri_path);

	/* Valid data should pass. */
	uri_path_create_and_compare(default_options, default_size, output_buffer, &output_buffer_size, ok, expected_default_path, strlen(expected_default_path));

	/* Empty option should pass. */
	struct o_coap_option empty_option[] = {
		{ .option_number = MAX_AGE },
		{ .option_number = URI_PATH, .value = "path", .len = 4 },
		{ .option_number = URI_PATH, .value = NULL, .len = 0 },
		{ .option_number = OSCORE },
		{ .option_number = URI_PATH, .value = "rsc", .len = 3 },
	};
	uint32_t empty_size = GET_ARRAY_SIZE(empty_option);
	uint8_t expected_empty_path[] = "path//rsc";
	uri_path_create_and_compare(empty_option, empty_size, output_buffer, &output_buffer_size, ok, expected_empty_path, strlen(expected_empty_path));
	
	/* No URI-Path option should pass. */
	struct o_coap_option no_options[] = {	
		{ .option_number = MAX_AGE },
		{ .option_number = OSCORE },
	};
	uint32_t no_options_size = GET_ARRAY_SIZE(no_options);
	uint8_t expected_no_options_path[] = "/";
	uri_path_create_and_compare(no_options, no_options_size, output_buffer, &output_buffer_size, ok, expected_no_options_path, strlen(expected_no_options_path));
}

void t404_get_observe_value(void)
{
	struct o_coap_option options_default[] = {
		{ .option_number = IF_NONE_MATCH },
		{ .option_number = OSCORE },
		{ .option_number = OBSERVE, .value = "\x00", .len = 1 },
	};
	struct o_coap_option options_long_observe[] = {
		{ .option_number = IF_NONE_MATCH },
		{ .option_number = OSCORE },
		{ .option_number = OBSERVE, .value = "\x00\x01\x02\x04", .len = 4 },
	};
	struct o_coap_option options_empty_observe[] = {
		{ .option_number = IF_NONE_MATCH },
		{ .option_number = OSCORE },
		{ .option_number = OBSERVE },
	};
	struct o_coap_option options_no_observe[] = {
		{ .option_number = IF_NONE_MATCH },
		{ .option_number = OSCORE },
	};

	/* Test null pointers. */
	struct byte_array output = BYTE_ARRAY_INIT(NULL, 0);
	get_observe_value_and_compare(NULL, 0, &output, false, NULL);
	get_observe_value_and_compare(options_default, 0, NULL, false, NULL);

	/* Test different valid values of the OBSERVE option. */
	struct byte_array expected_default = BYTE_ARRAY_INIT("\x00", 1);
	struct byte_array expected_long_observe = BYTE_ARRAY_INIT("\x00\x01\x02\x04", 4);
	struct byte_array expected_empty_observe = BYTE_ARRAY_INIT(NULL, 0);
	get_observe_value_and_compare(options_default, GET_ARRAY_SIZE(options_default), &output, true, &expected_default);
	get_observe_value_and_compare(options_long_observe, GET_ARRAY_SIZE(options_long_observe), &output, true, &expected_long_observe);
	get_observe_value_and_compare(options_empty_observe, GET_ARRAY_SIZE(options_empty_observe), &output, true, &expected_empty_observe);

	/* Test non-existing OBSERVE option. */
	get_observe_value_and_compare(options_no_observe, GET_ARRAY_SIZE(options_no_observe), &output, false, NULL);
}
