
#include <zephyr/zephyr.h>
#include <zephyr/ztest.h>

#include "oscore/oscore_coap.h"
#include "oscore/option.h"

#include "common/unit_test.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

static void print_options(struct o_coap_option *opt, uint8_t opt_cnt)
{
	uint8_t i;
	for (i = 0; i < opt_cnt; i++) {
		PRINTF("option_number: %d\n", opt[i].option_number);
		PRINT_ARRAY("value", opt[i].value, opt[i].len);
		PRINTF("delta: %d\n\n", opt[i].delta);
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
		.payload_len = 0,
		.payload = NULL,
	};

	struct o_coap_option inner_options[5];
	struct o_coap_option outer_options[5];
	uint16_t inner_options_len;
	uint8_t inner_options_cnt;
	uint8_t outer_options_cnt;

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

	struct o_coap_option expected_outer_options[] = {
		/*Proxy-Uri (opt num 35, U)*/
		{ .delta = 35,
		  .len = 0,
		  .value = NULL,
		  .option_number = PROXY_URI }
	};

	r = inner_outer_option_split(&coap_pkt, inner_options,
				     &inner_options_cnt, &inner_options_len,
				     outer_options, &outer_options_cnt);

	PRINT_MSG("\ninner options\n");
	print_options(inner_options, inner_options_cnt);
	PRINT_MSG("\nouter options\n");
	print_options(outer_options, outer_options_cnt);

	zassert_equal(r, ok, "Error in inner_outer_option_split. r: %d", r);

	zassert_mem_equal__(inner_options, expected_inner_options,
			    sizeof(expected_inner_options),
			    "inner options incorrect");

	zassert_mem_equal__(outer_options, expected_outer_options,
			    sizeof(expected_outer_options),
			    "inner options incorrect");
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
		.type = TYPE_CON,
		.TKL = 0,
		.code = CODE_REQ_POST,
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
		.payload_len = 0,
		.payload = NULL,
	};

	struct o_coap_option inner_options[5];
	struct o_coap_option outer_options[5];
	uint16_t inner_options_len;
	uint8_t inner_options_cnt;
	uint8_t outer_options_cnt;

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

	struct o_coap_option expected_outer_options[] = {
		/*Observe(opt num 6): The outer observe option may have 
        a value as in the original coap packet, see 4.1.3.5.2 in RFC8613*/
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

	r = inner_outer_option_split(&coap_pkt, inner_options,
				     &inner_options_cnt, &inner_options_len,
				     outer_options, &outer_options_cnt);

	PRINT_MSG("\ninner options\n");
	print_options(inner_options, inner_options_cnt);
	PRINT_MSG("\nouter options\n");
	print_options(outer_options, outer_options_cnt);

	zassert_equal(r, ok, "Error in inner_outer_option_split. r: %d", r);

	zassert_mem_equal__(inner_options, expected_inner_options,
			    sizeof(expected_inner_options),
			    "inner options incorrect");

	zassert_mem_equal__(outer_options, expected_outer_options,
			    sizeof(expected_outer_options),
			    "inner options incorrect");
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
		.payload_len = 0,
		.payload = NULL,
	};

	struct o_coap_option inner_options[5];
	struct o_coap_option outer_options[5];
	uint16_t inner_options_len;
	uint8_t inner_options_cnt;
	uint8_t outer_options_cnt;

	struct o_coap_option expected_inner_options[] = {
		/*If-Match (opt num 1, E)*/
		{ .delta = 1,
		  .len = 0,
		  .value = NULL,
		  .option_number = IF_MATCH },
		/*Etag (opt num 4, E)*/
		{ .delta = 3, .len = 0, .value = NULL, .option_number = ETAG },
		/*Observe(opt num 6): The inner observe option shall have 
        the value contained in the original coap packet, see 4.1.3.5.1 in RFC8613*/
		{ .delta = 2,
		  .len = sizeof(observe_val),
		  .value = observe_val,
		  .option_number = OBSERVE },
		/*Content-Format (opt num 12, E)*/
		{ .delta = 6,
		  .len = 0,
		  .value = NULL,
		  .option_number = CONTENT_FORMAT }

	};

	struct o_coap_option expected_outer_options[] = {
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

	r = inner_outer_option_split(&coap_pkt, inner_options,
				     &inner_options_cnt, &inner_options_len,
				     outer_options, &outer_options_cnt);
	zassert_equal(r, ok, "Error in inner_outer_option_split. r: %d", r);

	PRINT_MSG("\ninner options\n");
	print_options(inner_options, inner_options_cnt);
	PRINT_MSG("\nouter options\n");
	print_options(outer_options, outer_options_cnt);

	zassert_mem_equal__(inner_options, expected_inner_options,
			    sizeof(expected_inner_options),
			    "inner options incorrect");

	zassert_mem_equal__(outer_options, expected_outer_options,
			    sizeof(expected_outer_options),
			    "inner options incorrect");
}

/**
 * @brief   Tests oscore_pkg_generate with an observe option. 
 *          The observe option indicates registration.
 * 
 */
void t103_oscore_pkg_generate_request__with_observe_registration(void)
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
		.payload_len = 0,
		.payload = NULL,
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

	r = oscore_pkg_generate(&coap_pkt, &oscore_pkt, u_options,
				sizeof(u_options) /
					sizeof(struct o_coap_option),
				NULL, 0, &oscore_option);

	PRINTF("oscore_pkt code: %d\n", oscore_pkt.header.code);

	zassert_equal(r, ok, "Error in oscore_pkg_generate. r: %d", r);
}