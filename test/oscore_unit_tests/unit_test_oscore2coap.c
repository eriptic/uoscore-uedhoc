/*
   Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include "common/byte_array.h"
#include "common/unit_test.h"

#include "oscore/option.h"

void t300_oscore_option_parser_no_piv(void)
{
	enum err r;

	/*No PIV, some KID and some KID context*/

	struct compressed_oscore_option result;

	uint8_t kid_context[] = { "test KID context" };
	uint8_t kid[] = { "test KID" };

	struct compressed_oscore_option expected_result = {
		.h = 1,
		.k = 1,
		.n = 0,
		.piv.ptr = NULL,
		.piv.len = 0,
		.kid_context.ptr = kid_context,
		.kid_context.len = sizeof(kid_context),
		.kid.ptr = kid,
		.kid.len = sizeof(kid),
	};

	uint8_t val[2 + sizeof(kid_context) + sizeof(kid)];
	val[0] = 0b11000; /*set h and k flags */
	val[1] = sizeof(kid_context);
	memcpy(&val[2], kid_context, sizeof(kid_context));
	memcpy(&val[2 + sizeof(kid_context)], kid, sizeof(kid));

	struct o_coap_option opt = { .delta = 9,
				     .len = sizeof(val),
				     .value = val,
				     .option_number = OSCORE };

	r = oscore_option_parser(&opt, 1, &result);

	zassert_equal(r, ok, "Error in oscore_option_parser. r: %d", r);

	zassert_equal(result.h, expected_result.h, "wrong h");
	zassert_equal(result.k, expected_result.k, "wrong k");
	zassert_equal(result.n, expected_result.n, "wrong n");

	zassert_is_null(result.piv.ptr, "piv pointer not NULL");
	zassert_equal(result.piv.len, 0, "wrong piv len");
	zassert_mem_equal__(result.kid.ptr, expected_result.kid.ptr,
			    result.kid.len, "wrong kid");
	zassert_mem_equal__(result.kid_context.ptr,
			    expected_result.kid_context.ptr,
			    result.kid_context.len, "wrong kid_context");
}

void t301_oscore_option_parser_wrong_n(void)
{
	struct compressed_oscore_option result;
	enum err r;
	uint8_t val[] = { 6 }; /*set n = 6 */
	struct o_coap_option opt = { .delta = 9,
				     .len = sizeof(val),
				     .value = val,
				     .option_number = OSCORE };

	r = oscore_option_parser(&opt, 1, &result);
	zassert_equal(r, oscore_inpkt_invalid_piv,
		      "Error in oscore_option_parser. r: %d", r);

	val[0] = 7; /*set n = 7 */
	r = oscore_option_parser(&opt, 1, &result);
	zassert_equal(r, oscore_inpkt_invalid_piv,
		      "Error in oscore_option_parser. r: %d", r);
}

void t302_oscore_option_parser_no_kid(void)
{
	enum err r;

	/*No KID, some KID and some PIV context*/

	struct compressed_oscore_option result;

	uint8_t kid_context[] = { "test KID context" };
	uint8_t piv[] = { 0x01 };

	struct compressed_oscore_option expected_result = {
		.h = 1,
		.k = 0,
		.n = 1,
		.piv.ptr = piv,
		.piv.len = sizeof(piv),
		.kid_context.ptr = kid_context,
		.kid_context.len = sizeof(kid_context),
		.kid.ptr = NULL,
		.kid.len = 0,
	};

	uint8_t val[2 + sizeof(kid_context) + sizeof(piv)];
	val[0] = 0b10001; /*set h and n flags */
	memcpy(&val[1], piv, sizeof(piv));
	val[1 + sizeof(piv)] = sizeof(kid_context);
	memcpy(&val[2 + sizeof(piv)], kid_context, sizeof(kid_context));

	struct o_coap_option opt = { .delta = 9,
				     .len = sizeof(val),
				     .value = val,
				     .option_number = OSCORE };

	r = oscore_option_parser(&opt, 1, &result);

	zassert_equal(r, ok, "Error in oscore_option_parser. r: %d", r);

	zassert_equal(result.h, expected_result.h, "wrong h");
	zassert_equal(result.k, expected_result.k, "wrong k");
	zassert_equal(result.n, expected_result.n, "wrong n");

	zassert_is_null(result.kid.ptr, "piv pointer not NULL");
	zassert_equal(result.kid.len, 0, "wrong piv len");
	zassert_mem_equal__(result.piv.ptr, expected_result.piv.ptr,
			    result.piv.len, "wrong kid");
	zassert_mem_equal__(result.kid_context.ptr,
			    expected_result.kid_context.ptr,
			    result.kid_context.len, "wrong kid_context");
}

void t303_options_reorder(void)
{
	enum err r;

	struct o_coap_option u_options[] = {
		{ .delta = 7, .len = 0, .value = NULL, .option_number = 7 },
		{ .delta = 5, .len = 0, .value = NULL, .option_number = 12 }
	};

	struct o_coap_option e_options[] = {
		{ .delta = 2, .len = 0, .value = NULL, .option_number = 2 },
		{ .delta = 2, .len = 0, .value = NULL, .option_number = 4 }
	};

	struct o_coap_option expected[] = {
		{ .delta = 2, .len = 0, .value = NULL, .option_number = 2 },
		{ .delta = 2, .len = 0, .value = NULL, .option_number = 4 },
		{ .delta = 3, .len = 0, .value = NULL, .option_number = 7 },
		{ .delta = 5, .len = 0, .value = NULL, .option_number = 12 }
	};

	struct o_coap_option out[4];
	memset(&out, 0, sizeof(out));
	uint8_t out_cnt;

	r = options_reorder(u_options, 2, e_options, 2, out, &out_cnt);

	zassert_equal(r, ok, "Error in options_reorder. r: %d", r);

	//PRINT_ARRAY("out", out, sizeof(out));
	//PRINT_ARRAY("expected", expected, sizeof(expected));

	uint8_t i;
	uint8_t len = sizeof(out) / sizeof(out[0]);

	zassert_equal(out_cnt, len, "wrong option count");

	for (i = 0; i < len; i++) {
		zassert_equal(expected[i].delta, out[i].delta, "wrong delta");
		zassert_equal(expected[i].len, out[i].len, "wrong len");
		zassert_equal(expected[i].value, out[i].value, "wrong value");
		zassert_equal(expected[i].option_number, out[i].option_number,
			      "wrong option_number");
	}
}
