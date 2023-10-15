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

#include "oscore/oscore_coap.h"
#include "oscore/option.h"

static void coap_get_message_type_and_compare(struct o_coap_packet * coap_packet,  enum o_coap_msg * msg_type, enum err expected_result, enum o_coap_msg expected_msg_type)
{
	PRINTF("coap_get_message_type; expected result = %d\n", expected_result);
	enum err result = coap_get_message_type(coap_packet, msg_type);
	zassert_equal(expected_result, result, "unexpected result: %d", result);

	if (ok == result)
	{
		zassert_equal(*msg_type, expected_msg_type, "");
	}
}

static struct o_coap_packet generate_test_packet(uint8_t code, uint8_t options_count, uint8_t * observe_value, uint16_t observe_len)
{
	struct o_coap_packet result;
	result.header.code = code;
	result.options_cnt = options_count;
	result.options[0].option_number = OBSERVE;
	result.options[0].value = observe_value;
	result.options[0].len = observe_len;
	return result;
};

static void serialization_test(struct o_coap_option *options, uint8_t opt_cnt,
			       struct byte_array *expected)
{
	uint8_t out_buf[expected->len];
	struct byte_array out = BYTE_ARRAY_INIT(out_buf, sizeof(out_buf));

	enum err r = options_serialize(options, opt_cnt, &out);
	zassert_equal(r, ok, "Error in options_serialize. r: %d", r);

	PRINT_ARRAY("computed", out.ptr, out.len);
	PRINT_ARRAY("expected", expected->ptr, expected->len);

	zassert_mem_equal__(out.ptr, expected->ptr, expected->len,
			    "serialization incorrect");
}

static void deserialization_test(uint8_t *in_data, uint16_t in_data_len,
				 struct o_coap_option *options,
				 uint32_t options_len_in_byte)
{
	struct o_coap_packet coap_pkt;
	struct byte_array d = BYTE_ARRAY_INIT(in_data, in_data_len);
	enum err r =
		options_deserialize(&d,
				    (struct o_coap_option *)&coap_pkt.options,
				    &coap_pkt.options_cnt, &coap_pkt.payload);

	zassert_equal(r, ok, "Error in options_deserialize. r: %d", r);

	for (uint8_t i = 0; i < coap_pkt.options_cnt; i++) {
		zassert_equal(options[i].delta, coap_pkt.options[i].delta,
			      "delta mismatch: %d", coap_pkt.options[i].delta);
		zassert_equal(options[i].len, coap_pkt.options[i].len,
			      "len mismatch: %d", coap_pkt.options[i].len);
		zassert_equal(options[i].option_number,
			      coap_pkt.options[i].option_number,
			      "option_number mismatch: %d",
			      coap_pkt.options[i].option_number);
		zassert_mem_equal__(options[i].value, coap_pkt.options[i].value,
				    options[i].len, "option value mismatch");
	}
}

void t200_options_serialize_deserialize(void)
{
	/*
	* two options
	* short delta (delta < 12)
	* short data length (length < 12)
	*/
	uint8_t uri_host_val[] = { 'c', 'o', 'a', 'p', '.', 'm', 'e' };
	uint8_t uri_path_val[] = { 't', 'e', 's', 't' };
	struct o_coap_option options[] = { { .delta = 3,
					     .len = sizeof(uri_host_val),
					     .value = uri_host_val,
					     .option_number = URI_HOST },
					   { .delta = 8,
					     .len = sizeof(uri_path_val),
					     .value = uri_path_val,
					     .option_number = URI_PATH } };

	uint8_t EXPECTED[] = {
		0x37, 0x63, 0x6f, 0x61, 0x70, 0x2e, 0x6d,
		0x65, 0x84, 0x74, 0x65, 0x73, 0x74,
	};
	struct byte_array expt = BYTE_ARRAY_INIT(EXPECTED, sizeof(EXPECTED));

	serialization_test(options, sizeof(options) / sizeof(options[0]),
			   &expt);

	deserialization_test(EXPECTED, sizeof(EXPECTED), options,
			     sizeof(options));

	/*
    * four options
    * short delta (delta < 12)
    * short data length (length < 12)
    */
	uint8_t location_path1[] = {
		'l', 'o', 'c', 'a', 't', 'i', 'o', 'n', '1'
	};
	uint8_t location_path2[] = {
		'l', 'o', 'c', 'a', 't', 'i', 'o', 'n', '2'
	};
	uint8_t location_path3[] = {
		'l', 'o', 'c', 'a', 't', 'i', 'o', 'n', '3'
	};
	struct o_coap_option options1[] = { { .delta = 8,
					      .len = sizeof(location_path1),
					      .value = location_path1,
					      .option_number = LOCATION_PATH },
					    { .delta = 0,
					      .len = sizeof(location_path2),
					      .value = location_path2,
					      .option_number = LOCATION_PATH },
					    { .delta = 0,
					      .len = sizeof(location_path3),
					      .value = location_path3,
					      .option_number = LOCATION_PATH },
					    { .delta = 4,
					      .len = 0,
					      .value = NULL,
					      .option_number =
						      CONTENT_FORMAT } };

	uint8_t EXPECTED1[] = { 0x89, 0x6c, 0x6f, 0x63, 0x61, 0x74, 0x69, 0x6f,
				0x6e, 0x31, 0x09, 0x6c, 0x6f, 0x63, 0x61, 0x74,
				0x69, 0x6f, 0x6e, 0x32, 0x09, 0x6c, 0x6f, 0x63,
				0x61, 0x74, 0x69, 0x6f, 0x6e, 0x33, 0x40 };

	struct byte_array expt1 = BYTE_ARRAY_INIT(EXPECTED1, sizeof(EXPECTED1));

	serialization_test(options1, sizeof(options1) / sizeof(options1[0]),
			   &expt1);

	deserialization_test(EXPECTED1, sizeof(EXPECTED1), options1,
			     sizeof(options1));

	/*
    * three options
    * opt1 and opt2 short delta (delta < 12)
    * opt3 delta 16
    * short data length (length < 12)
    */
	uint8_t uri_host_val2[] = { 'c', 'o', 'a', 'p', '.', 'm', 'e' };
	uint8_t uri_path_val2[] = { 'l', 'a', 'r', 'g', 'e', '-',
				    'u', 'p', 'd', 'a', 't', 'e' };
	uint8_t block1_val[] = { 0x06 };
	struct o_coap_option options2[] = { { .delta = 3,
					      .len = sizeof(uri_host_val2),
					      .value = uri_host_val,
					      .option_number = URI_HOST },
					    { .delta = 8,
					      .len = sizeof(uri_path_val2),
					      .value = uri_path_val2,
					      .option_number = URI_PATH },
					    { .delta = 16,
					      .len = sizeof(block1_val),
					      .value = block1_val,
					      .option_number = BLOCK1 } };
	uint8_t EXPECTED2[] = { 0x37, 0x63, 0x6f, 0x61, 0x70, 0x2e, 0x6d, 0x65,
				0x8c, 0x6c, 0x61, 0x72, 0x67, 0x65, 0x2d, 0x75,
				0x70, 0x64, 0x61, 0x74, 0x65, 0xd1, 0x03, 0x06 };

	struct byte_array expt2 = BYTE_ARRAY_INIT(EXPECTED2, sizeof(EXPECTED2));

	serialization_test(options2, sizeof(options2) / sizeof(options2[0]),
			   &expt2);
	deserialization_test(EXPECTED2, sizeof(EXPECTED2), options2,
			     sizeof(options2));

	/*
    * one option
    * opt3 delta 13
    * short data length (length < 12)
    */
	uint8_t block1_val3[] = { 0x06 };
	struct o_coap_option options3[] = { { .delta = 27,
					      .len = sizeof(block1_val3),
					      .value = block1_val3,
					      .option_number = BLOCK1 } };
	uint8_t EXPECTED3[] = { 0xd1, 0x0e, 0x06 };

	struct byte_array expt3 = BYTE_ARRAY_INIT(EXPECTED3, sizeof(EXPECTED3));
	serialization_test(options3, sizeof(options3) / sizeof(options3[0]),
			   &expt3);
	deserialization_test(EXPECTED3, sizeof(EXPECTED3), options3,
			     sizeof(options3));

	/*
    * one option
    * delta 15
    * length 0
    */
	struct o_coap_option options4[] = { { .delta = 20,
					      .len = 0,
					      .value = NULL,
					      .option_number =
						      LOCATION_QUERY } };
	uint8_t EXPECTED4[] = { 0xd0, 0x07 };

	struct byte_array expt4 = BYTE_ARRAY_INIT(EXPECTED4, sizeof(EXPECTED4));
	serialization_test(options4, sizeof(options4) / sizeof(options4[0]),
			   &expt4);
	deserialization_test(EXPECTED4, sizeof(EXPECTED4), options4,
			     sizeof(options4));

	/*
    * one option
    * delta 780
    * length 0
    */
	struct o_coap_option options5[] = {
		{ .delta = 780, .len = 0, .value = NULL, .option_number = 780 }
	}; //there is no such option actually;)
	uint8_t EXPECTED5[] = { 0xe0, 0x01, 0xff };

	struct byte_array expt5 = BYTE_ARRAY_INIT(EXPECTED5, sizeof(EXPECTED5));
	serialization_test(options5, sizeof(options5) / sizeof(options5[0]),
			   &expt5);
	deserialization_test(EXPECTED5, sizeof(EXPECTED5), options5,
			     sizeof(options5));

	/*
    * one option
    * delta 280
    * length 500
    */
	uint8_t val7[500];
	memset(val7, 0, sizeof(val7));
	struct o_coap_option options7[] = { { .delta = 280,
					      .len = sizeof(val7),
					      .value = val7,
					      .option_number = 280 } };

	uint8_t EXPECTED7[505];
	memset(EXPECTED7, 0, sizeof(EXPECTED7));
	EXPECTED7[0] = 0xee;
	EXPECTED7[1] = 0x00;
	EXPECTED7[2] = 0x0b;
	EXPECTED7[3] = 0x00;
	EXPECTED7[4] = 0xe7;

	struct byte_array expt7 = BYTE_ARRAY_INIT(EXPECTED7, sizeof(EXPECTED7));
	serialization_test(options7, sizeof(options7) / sizeof(options7[0]),
			   &expt7);
	deserialization_test(EXPECTED7, sizeof(EXPECTED7), options7,
			     sizeof(options7));

	/*
    * one option
    * delta 22
    * length 500
    */
	uint8_t val8[500];
	memset(val8, 0, sizeof(val8));
	struct o_coap_option options8[] = { { .delta = 22,
					      .len = sizeof(val8),
					      .value = val8,
					      .option_number = 22 } };

	uint8_t EXPECTED8[504];
	memset(EXPECTED8, 0, sizeof(EXPECTED8));
	EXPECTED8[0] = 0xde;
	EXPECTED8[1] = 0x09;
	EXPECTED8[2] = 0x00;
	EXPECTED8[3] = 0xe7;

	struct byte_array expt8 = BYTE_ARRAY_INIT(EXPECTED8, sizeof(EXPECTED8));
	serialization_test(options8, sizeof(options8) / sizeof(options8[0]),
			   &expt8);
	deserialization_test(EXPECTED8, sizeof(EXPECTED8), options8,
			     sizeof(options8));
	/*
    * one option
    * delta 7
    * length 500  
    */
	uint8_t val9[500];
	memset(val9, 0, sizeof(val9));
	struct o_coap_option options9[] = { { .delta = 7,
					      .len = sizeof(val9),
					      .value = val9,
					      .option_number = 7 } };

	uint8_t EXPECTED9[503];
	memset(EXPECTED9, 0, sizeof(EXPECTED9));
	EXPECTED9[0] = 0x7e;
	EXPECTED9[1] = 0x00;
	EXPECTED9[2] = 0xe7;

	struct byte_array expt9 = BYTE_ARRAY_INIT(EXPECTED9, sizeof(EXPECTED9));
	serialization_test(options9, sizeof(options9) / sizeof(options9[0]),
			   &expt9);
	deserialization_test(EXPECTED9, sizeof(EXPECTED9), options9,
			     sizeof(options9));
	/*
    * one option
    * delta 500
    * length 20
    */
	uint8_t val10[20];
	memset(val10, 0, sizeof(val10));
	struct o_coap_option options10[] = { { .delta = 500,
					       .len = sizeof(val10),
					       .value = val10,
					       .option_number = 500 } };

	uint8_t EXPECTED10[24];
	memset(EXPECTED10, 0, sizeof(EXPECTED10));
	EXPECTED10[0] = 0xed;
	EXPECTED10[1] = 0x00;
	EXPECTED10[2] = 0xe7;
	EXPECTED10[3] = 0x07;

	struct byte_array expt10 =
		BYTE_ARRAY_INIT(EXPECTED10, sizeof(EXPECTED10));
	serialization_test(options10, sizeof(options10) / sizeof(options10[0]),
			   &expt10);
	deserialization_test(EXPECTED10, sizeof(EXPECTED10), options10,
			     sizeof(options10));
	/*
    * one option
    * delta 20
    * length 20
    */
	uint8_t val11[20];
	memset(val11, 0, sizeof(val11));
	struct o_coap_option options11[] = { { .delta = 20,
					       .len = sizeof(val11),
					       .value = val11,
					       .option_number = 20 } };

	uint8_t EXPECTED11[23];
	memset(EXPECTED11, 0, sizeof(EXPECTED11));
	EXPECTED11[0] = 0xdd;
	EXPECTED11[1] = 0x07;
	EXPECTED11[2] = 0x07;

	struct byte_array expt11 =
		BYTE_ARRAY_INIT(EXPECTED11, sizeof(EXPECTED11));
	serialization_test(options11, sizeof(options11) / sizeof(options11[0]),
			   &expt11);
	deserialization_test(EXPECTED11, sizeof(EXPECTED11), options11,
			     sizeof(options11));
	/*
    * one option
    * delta 4
    * length 20
    */
	uint8_t val12[20];
	memset(val12, 0, sizeof(val12));
	struct o_coap_option options12[] = { { .delta = 4,
					       .len = sizeof(val12),
					       .value = val12,
					       .option_number = 4 } };

	uint8_t EXPECTED12[22];
	memset(EXPECTED12, 0, sizeof(EXPECTED12));
	EXPECTED12[0] = 0x4d;
	EXPECTED12[1] = 0x07;

	struct byte_array expt12 =
		BYTE_ARRAY_INIT(EXPECTED12, sizeof(EXPECTED12));
	serialization_test(options12, sizeof(options12) / sizeof(options12[0]),
			   &expt12);
	deserialization_test(EXPECTED12, sizeof(EXPECTED12), options12,
			     sizeof(options12));

	/*
    * one option
    * delta 252
    * length 12
    */
	uint8_t val13[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
			    0x06, 0x07, 0x08, 0x09, 0x10, 0x11 };
	struct o_coap_option options13[] = { { .delta = 252,
					       .len = sizeof(val13),
					       .value = val13,
					       .option_number = ECHO } };
	uint8_t EXPECTED13[] = { 0xdc, 0xef, 0x00, 0x01, 0x02, 0x03, 0x04,
				 0x05, 0x06, 0x07, 0x08, 0x09, 0x10, 0x11 };

	struct byte_array expt13 =
		BYTE_ARRAY_INIT(EXPECTED13, sizeof(EXPECTED13));
	serialization_test(options13, sizeof(options13) / sizeof(options13[0]),
			   &expt13);
	deserialization_test(EXPECTED13, sizeof(EXPECTED13), options13,
			     sizeof(options13));
}

void t201_coap_serialize_deserialize(void)
{
	enum err r;
	/*test malformed input data*/
	struct byte_array in = BYTE_ARRAY_INIT(NULL, 0);
	struct o_coap_packet out;

	r = coap_deserialize(&in, &out);
	zassert_equal(r, not_valid_input_packet,
		      "Error in coap_deserialize. r: %d", r);

	/*test no token*/
	uint8_t in_buf[] = { 0x40, 0x00, 0x00, 0x00 };
	in.ptr = in_buf;
	in.len = sizeof(in_buf);

	r = coap_deserialize(&in, &out);
	zassert_equal(r, ok, "Error in coap_deserialize. r: %d", r);
	zassert_is_null(out.token, "invalid token");
	zassert_equal(out.header.TKL, 0, "invalid TKL");

	uint8_t ser_dat[sizeof(in_buf)];
	uint32_t ser_dat_len = 0;
	r = coap_serialize(&out, (uint8_t *)&ser_dat, &ser_dat_len);
	zassert_equal(r, ok, "Error in coap_deserialize. r: %d", r);
	zassert_equal(ser_dat_len, sizeof(in_buf), "wrong ser_dat_len");
	zassert_mem_equal__(ser_dat, in_buf, ser_dat_len, "wrong ser_dat");

	/*test too long token*/
	uint8_t in_buf_too_long_tkl[] = { 0x4F, 0x00, 0x00, 0x00 };
	in.ptr = in_buf_too_long_tkl;
	in.len = sizeof(in_buf_too_long_tkl);

	r = coap_deserialize(&in, &out);
	zassert_equal(r, oscore_inpkt_invalid_tkl,
		      "Error in coap_deserialize. r: %d", r);

	/*test valid tkl but no payload*/
	uint8_t in_buf_valid_tkl_no_payload[] = { 0x41, 0x00, 0x00, 0x00 };
	in.ptr = in_buf_valid_tkl_no_payload;
	in.len = sizeof(in_buf_valid_tkl_no_payload);

	r = coap_deserialize(&in, &out);
	zassert_equal(r, oscore_inpkt_invalid_tkl,
		      "Error in coap_deserialize. r: %d", r);
}

void t202_options_deserialize_corner_cases(void)
{
	enum err r;
	struct o_coap_packet coap_pkt;

	/*test only payload marker no payload*/
	uint8_t in_data1[] = { 0xff };
	struct byte_array d1 = BYTE_ARRAY_INIT(in_data1, sizeof(in_data1));

	r = options_deserialize(&d1, (struct o_coap_option *)&coap_pkt.options,
				&coap_pkt.options_cnt, &coap_pkt.payload);

	zassert_equal(r, not_valid_input_packet,
		      "Error in options_deserialize. r: %d", r);

	/*test invalid delta*/
	uint8_t in_data2[] = { 0xf0 }; //delta is 15 -> not a valid value
	struct byte_array d2 = BYTE_ARRAY_INIT(in_data2, sizeof(in_data2));

	r = options_deserialize(&d2, (struct o_coap_option *)&coap_pkt.options,
				&coap_pkt.options_cnt, &coap_pkt.payload);

	zassert_equal(r, oscore_inpkt_invalid_option_delta,
		      "Error in options_deserialize. r: %d", r);

	/*test invalid len*/
	uint8_t in_data3[] = { 0x0f }; //len is 15 -> not a valid value
	struct byte_array d3 = BYTE_ARRAY_INIT(in_data3, sizeof(in_data3));

	r = options_deserialize(&d3, (struct o_coap_option *)&coap_pkt.options,
				&coap_pkt.options_cnt, &coap_pkt.payload);

	zassert_equal(r, oscore_inpkt_invalid_optionlen,
		      "Error in options_deserialize. r: %d", r);

	/*test too many options*/
	uint8_t in_data4[] = {
		0x10, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
		0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00
	}; //21 options with option number 1
	struct byte_array d4 = BYTE_ARRAY_INIT(in_data4, sizeof(in_data4));

	r = options_deserialize(&d4, (struct o_coap_option *)&coap_pkt.options,
				&coap_pkt.options_cnt, &coap_pkt.payload);

	zassert_equal(r, too_many_options,
		      "Error in options_deserialize. r: %d", r);
}

void t203_coap_get_message_type(void)
{
	struct o_coap_packet packet_request_1 = generate_test_packet(CODE_REQ_GET, 0, NULL, 0); //no OBSERVE option
	struct o_coap_packet packet_request_2 = generate_test_packet(CODE_REQ_POST, 1, "\x01\x02\x03", 3);
	struct o_coap_packet packet_registration_1 = generate_test_packet(CODE_REQ_GET, 1, "\x00", 1);
	struct o_coap_packet packet_registration_2 = generate_test_packet(CODE_REQ_POST, 1, NULL, 0); //empty OBSERVE option
	struct o_coap_packet packet_cancellation = generate_test_packet(CODE_REQ_GET, 1, "\x01", 1);
	struct o_coap_packet packet_response = generate_test_packet(CODE_RESP_CONTENT, 0, NULL, 0);
	struct o_coap_packet packet_notification_1 = generate_test_packet(CODE_RESP_CONTENT, 1, NULL, 0);
	struct o_coap_packet packet_notification_2 = generate_test_packet(CODE_RESP_CONTENT, 1, "\x01\x02", 2);
	
	/* Test null pointers. */
	enum o_coap_msg msg_type;
	coap_get_message_type_and_compare(NULL, &msg_type, wrong_parameter, 0);
	coap_get_message_type_and_compare(&packet_request_1, NULL, wrong_parameter, 0);

	/* Test different valid packets. */
	coap_get_message_type_and_compare(&packet_request_1, &msg_type, ok, COAP_MSG_REQUEST);
	coap_get_message_type_and_compare(&packet_request_2, &msg_type, ok, COAP_MSG_REQUEST);
	coap_get_message_type_and_compare(&packet_registration_1, &msg_type, ok, COAP_MSG_REGISTRATION);
	coap_get_message_type_and_compare(&packet_registration_2, &msg_type, ok, COAP_MSG_REGISTRATION);
	coap_get_message_type_and_compare(&packet_cancellation, &msg_type, ok, COAP_MSG_CANCELLATION);
	coap_get_message_type_and_compare(&packet_response, &msg_type, ok, COAP_MSG_RESPONSE);
	coap_get_message_type_and_compare(&packet_notification_1, &msg_type, ok, COAP_MSG_NOTIFICATION);
	coap_get_message_type_and_compare(&packet_notification_2, &msg_type, ok, COAP_MSG_NOTIFICATION);
}
