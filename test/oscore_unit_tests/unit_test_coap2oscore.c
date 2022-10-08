
#include <zephyr/zephyr.h>
#include <zephyr/ztest.h>

#include "oscore/oscore_coap.h"

#include "common/unit_test.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

static void print_options(struct o_coap_option *opt, uint8_t opt_cnt)
{
	uint8_t i;
	for (i = 0; i < opt_cnt; i++) {
		PRINTF("delta: %d\n", opt[i].delta);
		PRINT_ARRAY("value", opt[i].value, opt[i].len);
		PRINTF("option_number: %d\n\n", opt[i].option_number);
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
			       .option_number = 1 },
                /*Etag (opt num 4, E)*/
			    { .delta = 3,
			       .len = 0,
			       .value = NULL,
			       .option_number = 4 },
                /*Content-Format (opt num 12, E)*/
			    { .delta = 8,
			       .len = 0,
			       .value = NULL,
			       .option_number = 12 } , 
                /*Proxy-Uri (opt num 35, U)*/
			    { .delta = 23,
			       .len = 0,
			       .value = NULL,
			       .option_number = 35 }
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
		{ .delta = 1, .len = 0, .value = NULL, .option_number = 1 },
		/*Etag (opt num 4, E)*/
		{ .delta = 3, .len = 0, .value = NULL, .option_number = 4 },
		/*Content-Format (opt num 12, E)*/
		{ .delta = 8, .len = 0, .value = NULL, .option_number = 12 }

	};

	struct o_coap_option expected_outer_options[] = {
		/*Proxy-Uri (opt num 35, U)*/
		{ .delta = 35, .len = 0, .value = NULL, .option_number = 35 }
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