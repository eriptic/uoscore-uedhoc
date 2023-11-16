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

#include "common/unit_test.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/byte_array.h"

#include "oscore/oscore_coap.h"
#include "oscore/option.h"

/* Use this function for debugging to print an array of options*/
static void print_options(struct o_coap_option *opt, uint8_t opt_cnt)
{
	uint8_t i;
	for (i = 0; i < opt_cnt; i++) {
		PRINTF("option_number: %d\n", opt[i].option_number);
		PRINT_ARRAY("value", opt[i].value, opt[i].len);
		PRINTF("delta: %d\n\n", opt[i].delta);
	}
}

static void assert_options(struct o_coap_option *opt,
			   struct o_coap_option *opt_expected, uint8_t opt_cnt,
			   uint8_t opt_cnt_expected)
{
	zassert_equal(opt_cnt, opt_cnt_expected, "wrong option count");

	for (uint8_t i = 0; i < opt_cnt; i++) {
		zassert_equal(opt[i].delta, opt_expected[i].delta,
			      "wrong delta");
		zassert_equal(opt[i].len, opt_expected[i].len, "wrong length");
		zassert_equal(opt[i].option_number,
			      opt_expected[i].option_number, "option_number");

		zassert_mem_equal__(opt[i].value, opt_expected[i].value,
				    opt[i].len, "wrong value");
	}
}

/**
 * @brief   Tests the function inner_outer_option_split without options
 *          with that require special processing.
 */
void t100_inner_outer_option_split__no_special_options(void)
{
	enum err r;

	struct o_coap_header header = {
		.ver = 1,
		.type = TYPE_CON,
		.TKL = 0,
		.code = CODE_REQ_POST,
		.MID = 0x0,
	};

	struct o_coap_packet coap_pkt = {
		.header = header,
		.token = NULL,
		.options_cnt = 4,
		.options = { 
                /*If-Match (opt num 1, E)*/
                { .delta = 1,
			       .len = 0,
			       .value = NULL,
			       .option_number = IF_MATCH },
                /*Etag (opt num 4, E)*/
			    { .delta = 3,
			       .len = 0,
			       .value = NULL,
			       .option_number = ETAG },
                /*Content-Format (opt num 12, E)*/
			    { .delta = 8,
			       .len = 0,
			       .value = NULL,
			       .option_number = 12 } , 
                /*Proxy-Uri (opt num 35, U)*/
			    { .delta = 23,
			       .len = 0,
			       .value = NULL,
			       .option_number = PROXY_URI }
                   },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	struct o_coap_option inner_options[5];
	struct o_coap_option outer_options[5];
	memset(inner_options, 0, sizeof(inner_options));
	memset(outer_options, 0, sizeof(outer_options));
	uint16_t inner_options_len = 0;
	uint8_t inner_options_cnt = 0;
	uint8_t outer_options_cnt = 0;
	uint8_t expected_inner_options_cnt;
	uint8_t expected_outer_options_cnt;

	struct o_coap_option expected_inner_options[] = {
		/*If-Match (opt num 1, E)*/
		{ .delta = 1,
		  .len = 0,
		  .value = NULL,
		  .option_number = IF_MATCH },
		/*Etag (opt num 4, E)*/
		{ .delta = 3, .len = 0, .value = NULL, .option_number = ETAG },
		/*Content-Format (opt num 12, E)*/
		{ .delta = 8,
		  .len = 0,
		  .value = NULL,
		  .option_number = CONTENT_FORMAT }

	};
	expected_inner_options_cnt = sizeof(expected_inner_options) /
				     sizeof(expected_inner_options[0]);

	struct o_coap_option expected_outer_options[] = {
		/*Proxy-Uri (opt num 35, U)*/
		{ .delta = 35,
		  .len = 0,
		  .value = NULL,
		  .option_number = PROXY_URI }
	};
	expected_outer_options_cnt = sizeof(expected_outer_options) /
				     sizeof(expected_outer_options[0]);

	r = inner_outer_option_split(&coap_pkt, inner_options,
				     &inner_options_cnt, &inner_options_len,
				     outer_options, &outer_options_cnt);

	PRINT_MSG("\ninner options\n");
	print_options(inner_options, inner_options_cnt);
	PRINT_MSG("\nouter options\n");
	print_options(outer_options, outer_options_cnt);

	zassert_equal(r, ok, "Error in inner_outer_option_split. r: %d", r);

	assert_options(inner_options, expected_inner_options, inner_options_cnt,
		       expected_inner_options_cnt);

	assert_options(outer_options, expected_outer_options, outer_options_cnt,
		       expected_outer_options_cnt);
}

/**
 * @brief   Tests the function inner_outer_option_split with Observe option 
 *          indicating a notification. This function tests the behavior of 
 *          the server preparing a response
 */
void t101_inner_outer_option_split__with_observe_notification(void)
{
	enum err r;

	struct o_coap_header header = {
		.ver = 1,
		.type = TYPE_ACK,
		.TKL = 0,
		.code = CODE_RESP_CONTENT,
		.MID = 0x0,
	};

	/*The Observe option value is a sequence number in notifications*/
	uint8_t observe_val[] = { 0x12 };

	struct o_coap_packet coap_pkt = {
		.header = header,
		.token = NULL,
		.options_cnt = 5,
		.options = { 
                /*If-Match (opt num 1, E)*/
                { .delta = 1,
			       .len = 0,
			       .value = NULL,
			       .option_number = IF_MATCH },
                /*Etag (opt num 4, E)*/
			    { .delta = 3,
			       .len = 0,
			       .value = NULL,
			       .option_number = ETAG },
                /*Observe (opt num 6, EU)*/
			    { .delta = 2,
			       .len = sizeof(observe_val),
			       .value = observe_val,
			       .option_number = OBSERVE },
                /*Content-Format (opt num 12, E)*/
			    { .delta = 6,
			       .len = 0,
			       .value = NULL,
			       .option_number = CONTENT_FORMAT } , 
                /*Proxy-Uri (opt num 35, U)*/
			    { .delta = 23,
			       .len = 0,
			       .value = NULL,
			       .option_number = PROXY_URI }
                   },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	struct o_coap_option inner_options[5];
	struct o_coap_option outer_options[5];
	memset(inner_options, 0, sizeof(inner_options));
	memset(outer_options, 0, sizeof(outer_options));
	uint16_t inner_options_len = 0;
	uint8_t inner_options_cnt = 0;
	uint8_t outer_options_cnt = 0;

	struct o_coap_option expected_inner_options[] = {
		/*If-Match (opt num 1, E)*/
		{ .delta = 1,
		  .len = 0,
		  .value = NULL,
		  .option_number = IF_MATCH },
		/*Etag (opt num 4, E)*/
		{ .delta = 3, .len = 0, .value = NULL, .option_number = ETAG },
		/*Observe(opt num 6): The inner observe option shall have 
        no value, see 4.1.3.5.2 in RFC8613*/
		{ .delta = 2,
		  .len = 0,
		  .value = NULL,
		  .option_number = OBSERVE },
		/*Content-Format (opt num 12, E)*/
		{ .delta = 6,
		  .len = 0,
		  .value = NULL,
		  .option_number = CONTENT_FORMAT }

	};
	uint8_t expected_inner_options_cnt =
		sizeof(expected_inner_options) / sizeof(struct o_coap_option);

	struct o_coap_option expected_outer_options[2];
	memset(expected_outer_options, 0, sizeof(expected_outer_options));
	/*Observe(opt num 6): The outer observe option may have 
        a value as in the original coap packet, see 4.1.3.5.2 in RFC8613*/
	expected_outer_options[0].delta = 6;
	expected_outer_options[0].len = sizeof(observe_val);
	expected_outer_options[0].value = observe_val;
	expected_outer_options[0].option_number = OBSERVE;

	/*Proxy-Uri (opt num 35, U)*/
	expected_outer_options[1].delta = 29;
	expected_outer_options[1].len = 0;
	expected_outer_options[1].value = NULL;
	expected_outer_options[1].option_number = PROXY_URI;

	uint8_t expected_outer_options_cnt =
		sizeof(expected_outer_options) / sizeof(struct o_coap_option);

	r = inner_outer_option_split(&coap_pkt, inner_options,
				     &inner_options_cnt, &inner_options_len,
				     outer_options, &outer_options_cnt);

	PRINT_MSG("\ninner options\n");
	print_options(inner_options, inner_options_cnt);
	PRINT_MSG("\nouter options\n");
	print_options(outer_options, outer_options_cnt);

	zassert_equal(r, ok, "Error in inner_outer_option_split. r: %d", r);

	assert_options(inner_options, expected_inner_options, inner_options_cnt,
		       expected_inner_options_cnt);

	assert_options(outer_options, expected_outer_options, outer_options_cnt,
		       expected_outer_options_cnt);
}

/**
 * @brief   Tests the function inner_outer_option_split with Observe option 
 *          indicating a registration. This function tests the behavior of 
 *          the client preparing a request
 */
void t102_inner_outer_option_split__with_observe_registration(void)
{
	enum err r;

	struct o_coap_header header = {
		.ver = 1,
		.type = TYPE_CON,
		.TKL = 0,
		.code = CODE_REQ_POST,
		.MID = 0x0,
	};

	/*The Observe option value is 0x00 when indicating a registration*/
	uint8_t observe_val[] = { 0x00 };

	struct o_coap_packet coap_pkt = {
		.header = header,
		.token = NULL,
		.options_cnt = 5,
		.options = { 
                /*If-Match (opt num 1, E)*/
                { .delta = 1,
			       .len = 0,
			       .value = NULL,
			       .option_number = IF_MATCH },
                /*Etag (opt num 4, E)*/
			    { .delta = 3,
			       .len = 0,
			       .value = NULL,
			       .option_number = ETAG },
                /*Observe (opt num 6, EU)*/
			    { .delta = 2,
			       .len = sizeof(observe_val),
			       .value = observe_val,
			       .option_number =  OBSERVE},
                /*Content-Format (opt num 12, E)*/
			    { .delta = 6,
			       .len = 0,
			       .value = NULL,
			       .option_number = CONTENT_FORMAT } , 
                /*Proxy-Uri (opt num 35, U)*/
			    { .delta = 23,
			       .len = 0,
			       .value = NULL,
			       .option_number = PROXY_URI }
                   },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	struct o_coap_option inner_options[5];
	struct o_coap_option outer_options[5];
	memset(inner_options, 0, sizeof(inner_options));
	memset(outer_options, 0, sizeof(outer_options));
	uint16_t inner_options_len = 0;
	uint8_t inner_options_cnt = 0;
	uint8_t outer_options_cnt = 0;

	struct o_coap_option expected_inner_options[4];
	memset(expected_inner_options, 0, sizeof(expected_inner_options));

	/*If-Match (opt num 1, E)*/
	expected_inner_options[0].delta = 1;
	expected_inner_options[0].len = 0;
	expected_inner_options[0].value = NULL;
	expected_inner_options[0].option_number = IF_MATCH;
	/*Etag (opt num 4, E)*/
	expected_inner_options[1].delta = 3;
	expected_inner_options[1].len = 0;
	expected_inner_options[1].value = NULL;
	expected_inner_options[1].option_number = ETAG;
	/*Observe(opt num 6): The inner observe option shall have 
        the value contained in the original coap packet, see 4.1.3.5.1 in RFC8613*/
	expected_inner_options[2].delta = 2;
	expected_inner_options[2].len = sizeof(observe_val);
	expected_inner_options[2].value = observe_val;
	expected_inner_options[2].option_number = OBSERVE;
	/*Content-Format (opt num 12, E)*/
	expected_inner_options[3].delta = 6;
	expected_inner_options[3].len = 0;
	expected_inner_options[3].value = NULL;
	expected_inner_options[3].option_number = CONTENT_FORMAT;

	struct o_coap_option expected_outer_options[2];
	memset(expected_outer_options, 0, sizeof(expected_outer_options));

	/*Observe(opt num 6): The outer observe option must have 
        a value as in the original coap packet, see 4.1.3.5.1 in RFC8613*/
	expected_outer_options[0].delta = 6;
	expected_outer_options[0].len = sizeof(observe_val);
	expected_outer_options[0].value = observe_val;
	expected_outer_options[0].option_number = OBSERVE;

	/*Proxy-Uri (opt num 35, U)*/
	expected_outer_options[1].delta = 29;
	expected_outer_options[1].len = 0;
	expected_outer_options[1].value = NULL;
	expected_outer_options[1].option_number = PROXY_URI;

	r = inner_outer_option_split(&coap_pkt, inner_options,
				     &inner_options_cnt, &inner_options_len,
				     outer_options, &outer_options_cnt);
	zassert_equal(r, ok, "Error in inner_outer_option_split. r: %d", r);

	PRINT_MSG("\ninner options\n");
	print_options(inner_options, inner_options_cnt);
	PRINT_MSG("\nouter options\n");
	print_options(outer_options, outer_options_cnt);

	uint8_t expected_inner_options_cnt =
		sizeof(expected_inner_options) / sizeof(struct o_coap_option);
	uint8_t expected_outer_options_cnt =
		sizeof(expected_outer_options) / sizeof(struct o_coap_option);
	assert_options(inner_options, expected_inner_options, inner_options_cnt,
		       expected_inner_options_cnt);

	assert_options(outer_options, expected_outer_options, outer_options_cnt,
		       expected_outer_options_cnt);
}

/**
 * @brief   Tests oscore_pkg_generate with an observe option. 
 *          The observe option indicates registration, which is a 
 * 			request message.
 * 
 */
void t103_oscore_pkg_generate__request_with_observe_registration(void)
{
	enum err r;

	struct o_coap_header header = {
		.ver = 1,
		.type = TYPE_CON,
		.TKL = 0,
		.code = CODE_REQ_POST,
		.MID = 0x0,
	};

	/*The Observe option value is 0x00 when indicating a registration*/
	uint8_t observe_val[] = { 0x00 };

	struct o_coap_packet coap_pkt = {
		.header = header,
		.token = NULL,
		.options_cnt = 5,
		.options = { 
                /*If-Match (opt num 1, E)*/
                { .delta = 1,
			       .len = 0,
			       .value = NULL,
			       .option_number = IF_MATCH },
                /*Etag (opt num 4, E)*/
			    { .delta = 3,
			       .len = 0,
			       .value = NULL,
			       .option_number = ETAG },
                /*Observe (opt num 6, EU)*/
			    { .delta = 2,
			       .len = sizeof(observe_val),
			       .value = observe_val,
			       .option_number = OBSERVE },
                /*Content-Format (opt num 12, E)*/
			    { .delta = 6,
			       .len = 0,
			       .value = NULL,
			       .option_number = CONTENT_FORMAT } , 
                /*Proxy-Uri (opt num 35, U)*/
			    { .delta = 23,
			       .len = 0,
			       .value = NULL,
			       .option_number = PROXY_URI }
                   },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	struct o_coap_option u_options[] = {
		/*Observe(opt num 6): The outer observe option must have 
        a value as in the original coap packet, see 4.1.3.5.1 in RFC8613*/
		{ .delta = 6,
		  .len = sizeof(observe_val),
		  .value = observe_val,
		  .option_number = OBSERVE },
		/*Proxy-Uri (opt num 35, U)*/
		{ .delta = 29,
		  .len = 0,
		  .value = NULL,
		  .option_number = PROXY_URI }
	};

	struct oscore_option oscore_option = {
		.delta = 0, .len = 0, .value = NULL, .option_number = OSCORE
	};

	struct o_coap_packet oscore_pkt;
	memset(&oscore_pkt, 0, sizeof(oscore_pkt));

	struct o_coap_header expected_oscore_header = {
		.ver = 1,
		.type = TYPE_CON,
		.TKL = 0,
		.code = CODE_REQ_FETCH,
		.MID = 0x0,
	};
	struct o_coap_packet expected_oscore_pkt = {
		.header = expected_oscore_header,
		.token = NULL,
		.options_cnt = 3,
		.options = { { .delta = 6,
			       .len = sizeof(observe_val),
			       .value = observe_val,
			       .option_number = OBSERVE },
			     { .delta = 3,
			       .len = 0,
			       .value = NULL,
			       .option_number = OSCORE },
			     { .delta = 26,
			       .len = 0,
			       .value = NULL,
			       .option_number = PROXY_URI } },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	struct byte_array no_ciphertext = { .ptr = NULL, .len = 0 };
	r = oscore_pkg_generate(&coap_pkt, &oscore_pkt, u_options, 2,
				&no_ciphertext, &oscore_option);

	zassert_equal(r, ok, "Error in oscore_pkg_generate. r: %d", r);

	// PRINTF("coap_pkt code: %02X\n", coap_pkt.header.code);
	// PRINTF("oscore_pkt code: %02X\n", oscore_pkt.header.code);

	// PRINT_ARRAY("oscore_pkt", &oscore_pkt, sizeof(oscore_pkt));
	// PRINT_ARRAY("oscore_pkt options", &oscore_pkt.options,
	// 	    sizeof(oscore_pkt.options));
	// PRINT_ARRAY("expected_oscore_pkt", &expected_oscore_pkt,
	// 	    sizeof(expected_oscore_pkt));
	// PRINT_ARRAY("expected_oscore_pkt options", &expected_oscore_pkt.options,
	// 	    sizeof(expected_oscore_pkt.options));

	zassert_mem_equal__(&oscore_pkt, &expected_oscore_pkt,
			    sizeof(oscore_pkt), "oscore_pkt incorrect");
}

/**
 * @brief   Tests oscore_pkg_generate with an observe option. 
 *          The observe option indicates notification.
 * 			The message is a response.
 * 
 */
void t104_oscore_pkg_generate__request_with_observe_notification(void)
{
	enum err r;

	struct o_coap_header header = {
		.ver = 1,
		.type = TYPE_ACK,
		.TKL = 0,
		.code = CODE_RESP_CONTENT,
		.MID = 0x0,
	};

	/*The Observe option value is 0x00 when indicating a registration*/
	uint8_t observe_val[] = { 0xde, 0xad, 0xbe, 0xaf };

	struct o_coap_packet coap_pkt = {
		.header = header,
		.token = NULL,
		.options_cnt = 1,
		.options = { 
                /*Observe (opt num 6, EU)*/
			    { .delta = 6,
			       .len = sizeof(observe_val),
			       .value = observe_val,
			       .option_number = OBSERVE },
                   },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	struct o_coap_option u_options[] = {
		/*Observe(opt num 6): The outer observe option may have 
        a value as in the original coap packet, see 4.1.3.5.1 in RFC8613*/
		{ .delta = 6,
		  .len = sizeof(observe_val),
		  .value = observe_val,
		  .option_number = OBSERVE }
	};
	uint8_t u_options_len =
		sizeof(u_options) / sizeof(struct o_coap_option);

	struct oscore_option oscore_option = {
		.delta = 0, .len = 0, .value = NULL, .option_number = OSCORE
	};

	struct o_coap_packet oscore_pkt;
	memset(&oscore_pkt, 0, sizeof(oscore_pkt));

	struct o_coap_header expected_oscore_header = {
		.ver = 1,
		.type = TYPE_ACK,
		.TKL = 0,
		.code = CODE_RESP_CONTENT,
		.MID = 0x0,
	};
	struct o_coap_packet expected_oscore_pkt = {
		.header = expected_oscore_header,
		.token = NULL,
		.options_cnt = 2,
		.options = { { .delta = 6,
			       .len = sizeof(observe_val),
			       .value = observe_val,
			       .option_number = OBSERVE },
			     { .delta = 3,
			       .len = 0,
			       .value = NULL,
			       .option_number = OSCORE } },
		.payload.len = 0,
		.payload.ptr = NULL,
	};
	struct byte_array no_ciphertext = { .ptr = NULL, .len = 0 };
	r = oscore_pkg_generate(&coap_pkt, &oscore_pkt, u_options,
				u_options_len, &no_ciphertext, &oscore_option);

	zassert_equal(r, ok, "Error in oscore_pkg_generate. r: %d", r);

	// PRINTF("coap_pkt code: %02X\n", coap_pkt.header.code);
	// PRINTF("oscore_pkt code: %02X\n", oscore_pkt.header.code);

	// PRINT_ARRAY("oscore_pkt", &oscore_pkt, sizeof(oscore_pkt));
	// PRINT_ARRAY("oscore_pkt options", &oscore_pkt.options,
	// 	    sizeof(oscore_pkt.options));
	// PRINT_ARRAY("expected_oscore_pkt", &expected_oscore_pkt,
	// 	    sizeof(expected_oscore_pkt));
	// PRINT_ARRAY("expected_oscore_pkt options", &expected_oscore_pkt.options,
	// 	    sizeof(expected_oscore_pkt.options));

	zassert_mem_equal__(&oscore_pkt, &expected_oscore_pkt,
			    sizeof(oscore_pkt), "oscore_pkt incorrect");
}

/**
 * @brief   Tests the function inner_outer_option_split with too many options
 */
void t105_inner_outer_option_split__too_many_options(void)
{
	enum err r;

	struct o_coap_header header = {
		.ver = 1,
		.type = TYPE_CON,
		.TKL = 0,
		.code = CODE_REQ_POST,
		.MID = 0x0,
	};

	struct o_coap_packet coap_pkt = {
		.header = header,
		.token = NULL,
		.options_cnt = 21,
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	struct o_coap_option inner_options[5];
	struct o_coap_option outer_options[5];
	memset(inner_options, 0, sizeof(inner_options));
	memset(outer_options, 0, sizeof(outer_options));
	uint16_t inner_options_len = 0;
	uint8_t inner_options_cnt = 0;
	uint8_t outer_options_cnt = 0;

	r = inner_outer_option_split(&coap_pkt, inner_options,
				     &inner_options_cnt, &inner_options_len,
				     outer_options, &outer_options_cnt);
	zassert_equal(r, too_many_options,
		      "Error in inner_outer_option_split. r: %d", r);
}

/**
 * @brief create an OSCORE option without a PIV
*/
void t106_oscore_option_generate_no_piv(void)
{
	struct oscore_option oscore_option;

	uint8_t val[] = { 0b11000, 1, 1, 1 };
	struct oscore_option expected = {
		.delta = OSCORE,
		.len = sizeof(val),
		.value = val,
		.option_number = OSCORE,
	};

	uint8_t kid_buf[] = { 1 };
	uint8_t kid_context_buf[] = { 1 };

	struct byte_array piv = BYTE_ARRAY_INIT(NULL, 0);
	struct byte_array kid = BYTE_ARRAY_INIT(kid_buf, sizeof(kid_buf));
	struct byte_array kid_context =
		BYTE_ARRAY_INIT(kid_context_buf, sizeof(kid_context_buf));

	enum err r = oscore_option_generate(&piv, &kid, &kid_context,
					    &oscore_option);

	zassert_equal(r, ok, "Error in oscore_option_generate. r: %d", r);
	zassert_equal(oscore_option.len, expected.len,
		      "wrong oscore option len");
	zassert_equal(oscore_option.option_number, expected.option_number,
		      "wrong oscore option_number");
	zassert_mem_equal__(oscore_option.value, expected.value,
			    oscore_option.len, "wrong oscore option value");
	;
}