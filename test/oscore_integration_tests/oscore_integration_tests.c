/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include "oscore.h"

#include "oscore_test_vectors.h"

#include "oscore/oscore_coap.h"
#include "oscore/option.h"

#include "common/print_util.h"

enum reverse_t {
	NORMAL,
	REVERSED
};

enum freshness_t {
	FRESH,
	RESTORED
};

static struct oscore_init_params get_default_params(enum reverse_t is_reversed, enum freshness_t is_fresh)
{
	struct byte_array sender = { .ptr = (uint8_t *)T1__SENDER_ID, .len = T1__SENDER_ID_LEN };
	struct byte_array recipient = { .ptr = (uint8_t *)T1__RECIPIENT_ID, .len = T1__RECIPIENT_ID_LEN };

	struct oscore_init_params params = {
		.master_secret.ptr = (uint8_t *)T1__MASTER_SECRET,
		.master_secret.len = T1__MASTER_SECRET_LEN,
		.sender_id = (is_reversed == NORMAL) ? sender : recipient,
		.recipient_id = (is_reversed == NORMAL) ? recipient : sender,
		.master_salt.ptr = (uint8_t *)T1__MASTER_SALT,
		.master_salt.len = T1__MASTER_SALT_LEN,
		.id_context.ptr = (uint8_t *)T1__ID_CONTEXT,
		.id_context.len = T1__ID_CONTEXT_LEN,
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = (is_fresh == FRESH),
	};
	return params;
}

/**
 * Test 1:
 * - Client Key derivation with master salt see RFC8613 Appendix C.1.1
 * - Generating OSCORE request with key form C.1.1 see RFC8613 Appendix C.4
 */
void t1_oscore_client_request_response(void)
{
	enum err r;
	struct context c_client;
	struct oscore_init_params params = get_default_params(NORMAL, RESTORED);

	r = oscore_context_init(&params, &c_client);

	zassert_equal(r, ok, "Error in oscore_context_init");

	/*
    required only for the test vector.
    during normal operation the sender sequence number is
    increased automatically after every sending
    */
	//c_client.sc.ssn = 20;

	uint8_t buf_oscore[256];
	uint32_t buf_oscore_len = sizeof(buf_oscore);
	uint8_t buf_coap[256];
	uint32_t buf_coap_len = sizeof(buf_coap);

	/*test converting the request*/
	r = coap2oscore((uint8_t *)T1__COAP_REQ, T1__COAP_REQ_LEN,
			(uint8_t *)&buf_oscore, &buf_oscore_len, &c_client);
	zassert_equal(r, ok, "Error in coap2oscore!");

	zassert_mem_equal__(c_client.sc.sender_key.ptr, T1__SENDER_KEY,
			    c_client.sc.sender_key.len,
			    "T1 sender key derivation failed");

	zassert_mem_equal__(c_client.rc.recipient_key.ptr, T1__RECIPIENT_KEY,
			    c_client.rc.recipient_key.len,
			    "T1 recipient key derivation failed");

	zassert_mem_equal__(c_client.cc.common_iv.ptr, T1__COMMON_IV,
			    c_client.cc.common_iv.len,
			    "T1 common IV derivation failed");

	zassert_mem_equal__(&buf_oscore, T1__OSCORE_REQ, T1__OSCORE_REQ_LEN,
			    "coap2oscore failed");

	/*test converting the response*/
	r = oscore2coap((uint8_t *)T1__OSCORE_RESP, T1__OSCORE_RESP_LEN,
			(uint8_t *)&buf_coap, &buf_coap_len, &c_client);
	zassert_equal(r, ok, "Error in coap2oscore!");
	zassert_mem_equal__(&buf_coap, T1__COAP_RESPONSE, T1__COAP_RESPONSE_LEN,
			    "coap2oscore failed");
}

/**
 * Test 3:
 * - Client Key derivation without master salt see RFC8613 Appendix C.2.1
 * - Generating OSCORE request with key form C.2.1 see RFC8613 Appendix C.5
 */
void t3_oscore_client_request(void)
{
	enum err r;
	struct context c_client;
	struct oscore_init_params params = {
		.master_secret.ptr = (uint8_t *)T3__MASTER_SECRET,
		.master_secret.len = T3__MASTER_SECRET_LEN,
		.sender_id.ptr = (uint8_t *)T3__SENDER_ID,
		.sender_id.len = T3__SENDER_ID_LEN,
		.recipient_id.ptr = (uint8_t *)T3__RECIPIENT_ID,
		.recipient_id.len = T3__RECIPIENT_ID_LEN,
		.master_salt.ptr = (uint8_t *)T3__MASTER_SALT,
		.master_salt.len = T3__MASTER_SALT_LEN,
		.id_context.ptr = (uint8_t *)T3__ID_CONTEXT,
		.id_context.len = T3__ID_CONTEXT_LEN,
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = true,
	};

	r = oscore_context_init(&params, &c_client);

	zassert_equal(r, ok, "Error in oscore_context_init");

	/*
    required only for the test vector.
    during normal operation the sender sequence number is
    increased automatically after every sending
    */
	c_client.sc.ssn = 20;

	uint8_t buf_oscore[256];
	uint32_t buf_oscore_len = sizeof(buf_oscore);

	r = coap2oscore((uint8_t *)T3__COAP_REQ, T3__COAP_REQ_LEN,
			(uint8_t *)&buf_oscore, &buf_oscore_len, &c_client);

	zassert_equal(r, ok, "Error in coap2oscore!");

	zassert_mem_equal__(&buf_oscore, T3__OSCORE_REQ, T3__OSCORE_REQ_LEN,
			    "coap2oscore failed");
}

/**
 * Test 5 :
 * - Client Key derivation with ID Context see Appendix 3.1
 * - OSCORE request generation see Appendix C6
 */
void t5_oscore_client_request(void)
{
	enum err r;
	struct context c_client;
	struct oscore_init_params params = {
		.master_secret.ptr = (uint8_t *)T5__MASTER_SECRET,
		.master_secret.len = T5__MASTER_SECRET_LEN,
		.sender_id.ptr = (uint8_t *)T5__SENDER_ID,
		.sender_id.len = T5__SENDER_ID_LEN,
		.recipient_id.ptr = (uint8_t *)T5__RECIPIENT_ID,
		.recipient_id.len = T5__RECIPIENT_ID_LEN,
		.master_salt.ptr = (uint8_t *)T5__MASTER_SALT,
		.master_salt.len = T5__MASTER_SALT_LEN,
		.id_context.ptr = (uint8_t *)T5__ID_CONTEXT,
		.id_context.len = T5__ID_CONTEXT_LEN,
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = true,
	};

	r = oscore_context_init(&params, &c_client);

	zassert_equal(r, ok, "Error in oscore_context_init");

	/*
    required only for the test vector.
    during normal operation the sender sequence number is
    increased automatically after every sending
    */
	c_client.sc.ssn = 20;

	uint8_t buf_oscore[256];
	uint32_t buf_oscore_len = sizeof(buf_oscore);

	r = coap2oscore((uint8_t *)T5__COAP_REQ, T5__COAP_REQ_LEN,
			(uint8_t *)&buf_oscore, &buf_oscore_len, &c_client);

	zassert_equal(r, ok, "Error in coap2oscore!");

	zassert_mem_equal__(&buf_oscore, T5__OSCORE_REQ, buf_oscore_len,
			    "coap2oscore failed");
}

/**
 * Test 2:
 * - Server Key derivation with master salt see RFC8613 Appendix C.1.2
 * - Generating OSCORE response with key form C.1.2 see RFC8613 Appendix C.7
 */
void t2_oscore_server_request_response(void)
{
	enum err r;
	struct context c_server;
	struct oscore_init_params params_server = {
		.master_secret.ptr = (uint8_t *)T2__MASTER_SECRET,
		.master_secret.len = T2__MASTER_SECRET_LEN,
		.sender_id.ptr = (uint8_t *)T2__SENDER_ID,
		.sender_id.len = T2__SENDER_ID_LEN,
		.recipient_id.ptr = (uint8_t *)T2__RECIPIENT_ID,
		.recipient_id.len = T2__RECIPIENT_ID_LEN,
		.master_salt.ptr = (uint8_t *)T2__MASTER_SALT,
		.master_salt.len = T2__MASTER_SALT_LEN,
		.id_context.ptr = (uint8_t *)T2__ID_CONTEXT,
		.id_context.len = T2__ID_CONTEXT_LEN,
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = true,
	};

	r = oscore_context_init(&params_server, &c_server);

	zassert_equal(r, ok, "Error in oscore_context_init");

	/*Test decrypting of an incoming request*/
	uint8_t buf_coap[256];
	uint32_t buf_coap_len = sizeof(buf_coap);

	r = oscore2coap((uint8_t *)T2__OSCORE_REQ, T2__OSCORE_REQ_LEN, buf_coap,
			&buf_coap_len, &c_server);

	zassert_equal(r, ok, "Error in oscore2coap! Error code: %d", r);
	zassert_mem_equal__(&buf_coap, T2__COAP_REQ, buf_coap_len,
			    "oscore2coap failed");

	/*test response not matching the recipient ID*/
	uint8_t wrong_recipient_id[] = { 0x02 };
	c_server.rc.recipient_id.ptr = wrong_recipient_id;
	c_server.rc.recipient_id.len = sizeof(wrong_recipient_id);

	r = oscore2coap((uint8_t *)T2__OSCORE_REQ, T2__OSCORE_REQ_LEN,
			(uint8_t *)&buf_coap, &buf_coap_len, &c_server);
	zassert_equal(r, oscore_kid_recipient_id_mismatch,
		      "Error in coap2oscore!");

	/*Test generating an encrypted response, see Appendix C7*/
	uint8_t buf_oscore[256];
	uint32_t buf_oscore_len = sizeof(buf_oscore);

	r = coap2oscore((uint8_t *)T2__COAP_RESPONSE, T2__COAP_RESPONSE_LEN,
			(uint8_t *)&buf_oscore, &buf_oscore_len, &c_server);

	zassert_equal(r, ok, "Error in coap2oscore");

	zassert_mem_equal__(&buf_oscore, T2__OSCORE_RESP, buf_oscore_len,
			    "coap2oscore failed");
}

void t4_oscore_server_key_derivation(void)
{
	enum err r;
	struct context c_server;
	struct oscore_init_params params_server = {
		.master_secret.ptr = (uint8_t *)T4__MASTER_SECRET,
		.master_secret.len = T4__MASTER_SECRET_LEN,
		.sender_id.ptr = (uint8_t *)T4__SENDER_ID,
		.sender_id.len = T4__SENDER_ID_LEN,
		.recipient_id.ptr = (uint8_t *)T4__RECIPIENT_ID,
		.recipient_id.len = T4__RECIPIENT_ID_LEN,
		.master_salt.ptr = (uint8_t *)T4__MASTER_SALT,
		.master_salt.len = T4__MASTER_SALT_LEN,
		.id_context.ptr = (uint8_t *)T4__ID_CONTEXT,
		.id_context.len = T4__ID_CONTEXT_LEN,
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = true,
	};

	r = oscore_context_init(&params_server, &c_server);

	zassert_equal(r, ok, "Error in oscore_context_init");

	zassert_mem_equal__(c_server.sc.sender_key.ptr, T4__SENDER_KEY,
			    c_server.sc.sender_key.len,
			    "T4 sender key derivation failed");

	zassert_mem_equal__(c_server.rc.recipient_key.ptr, T4__RECIPIENT_KEY,
			    c_server.rc.recipient_key.len,
			    "T4 recipient key derivation failed");

	zassert_mem_equal__(c_server.cc.common_iv.ptr, T4__COMMON_IV,
			    c_server.cc.common_iv.len,
			    "T4 common IV derivation failed");
}

/**
 * Test 6:
 * - Server Key derivation with ID context see RFC8613 Appendix C.3.2
 */
void t6_oscore_server_key_derivation(void)
{
	enum err r;
	struct context c_server;
	struct oscore_init_params params_server = {
		.master_secret.ptr = (uint8_t *)T6__MASTER_SECRET,
		.master_secret.len = T6__MASTER_SECRET_LEN,
		.sender_id.ptr = (uint8_t *)T6__SENDER_ID,
		.sender_id.len = T6__SENDER_ID_LEN,
		.recipient_id.ptr = (uint8_t *)T6__RECIPIENT_ID,
		.recipient_id.len = T6__RECIPIENT_ID_LEN,
		.master_salt.ptr = (uint8_t *)T6__MASTER_SALT,
		.master_salt.len = T6__MASTER_SALT_LEN,
		.id_context.ptr = (uint8_t *)T6__ID_CONTEXT,
		.id_context.len = T6__ID_CONTEXT_LEN,
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = true,
	};

	r = oscore_context_init(&params_server, &c_server);

	zassert_equal(r, ok, "Error in oscore_context_init");

	zassert_mem_equal__(c_server.sc.sender_key.ptr, T6__SENDER_KEY,
			    c_server.sc.sender_key.len,
			    "T6 sender key derivation failed");

	zassert_mem_equal__(c_server.rc.recipient_key.ptr, T6__RECIPIENT_KEY,
			    c_server.rc.recipient_key.len,
			    "T6 recipient key derivation failed");

	zassert_mem_equal__(c_server.cc.common_iv.ptr, T6__COMMON_IV,
			    c_server.cc.common_iv.len,
			    "T6 common IV derivation failed");
}

/**
 * Test 8:
 * - Simple ACK packet should not be encrypted and result should be the same as input buffer (see RFC8613 Section 4.2)
 */
void t8_oscore_server_response_simple_ack(void)
{
	enum err r;
	struct context context;
	struct oscore_init_params params = {
		.master_secret.ptr = (uint8_t *)T7__MASTER_SECRET,
		.master_secret.len = T7__MASTER_SECRET_LEN,
		.sender_id.ptr = (uint8_t *)T7__SENDER_ID,
		.sender_id.len = T7__SENDER_ID_LEN,
		.recipient_id.ptr = (uint8_t *)T7__RECIPIENT_ID,
		.recipient_id.len = T7__RECIPIENT_ID_LEN,
		.master_salt.ptr = (uint8_t *)T7__MASTER_SALT,
		.master_salt.len = T7__MASTER_SALT_LEN,
		.id_context.ptr = (uint8_t *)T7__ID_CONTEXT,
		.id_context.len = T7__ID_CONTEXT_LEN,
		.aead_alg = OSCORE_AES_CCM_16_64_128,
		.hkdf = OSCORE_SHA_256,
		.fresh_master_secret_salt = true,
	};

	r = oscore_context_init(&params, &context);

	zassert_equal(r, ok, "Error in oscore_context_init");

	/*Test if encrypting simple ACK message results in valid unencrypted message, see Section 4.2*/
	uint8_t buf_oscore[256];
	uint32_t buf_oscore_len = sizeof(buf_oscore);

	r = coap2oscore((uint8_t *)T8__COAP_ACK, T8__COAP_ACK_LEN,
			(uint8_t *)&buf_oscore, &buf_oscore_len, &context);

	zassert_equal(r, ok, "Error in coap2oscore");

	zassert_mem_equal__(&buf_oscore, T8__COAP_ACK, T8__COAP_ACK_LEN,
			    "coap2oscore failed");

	zassert_equal(buf_oscore_len, T8__COAP_ACK_LEN, "coap2oscore failed");
}

/**
 * @brief	This function test the behavior of a server and a client in a typical
 * 			observe exchange as depicted:
 *
 *			client							server
 *			---------						---------
 *				|								|
 *				|------registration------------>|
 *				|								|
 *				|<-----notification1------------|
 * rejected msg	| x---replayed notification1----|
 *				|								|
 *
 * 			See as well Appendix A.1. in RFC7641
 */
void t9_oscore_client_server_observe(void)
{
	/*
	 *
	 * Initialize contexts for the client and server
	 *
	 */
	enum err r;
	struct context c_client;
	struct oscore_init_params params_client = get_default_params(NORMAL, FRESH);
	r = oscore_context_init(&params_client, &c_client);
	zassert_equal(r, ok, "Error in oscore_context_init for client");

	struct context c_server;
	struct oscore_init_params params_server = get_default_params(REVERSED, FRESH);
	r = oscore_context_init(&params_server, &c_server);
	zassert_equal(r, ok, "Error in oscore_context_init for server");

	/*
	 *
	 *test the registration (first request)
	 *
	 */
	PRINT_MSG("\n\n |------registration---->| \n\n");
	uint8_t observe_val[] = { 0x00 }; /*0x00 indicates registration*/
	uint8_t uri_path_val[] = { 't', 'e', 'm', 'p', 'e', 'r',
				   'a', 't', 'u', 'r', 'e' };
	uint8_t token[] = { 0x4a };
	uint8_t ser_coap_pkt_registration[40];
	uint32_t ser_coap_pkt_registration_len =
		sizeof(ser_coap_pkt_registration);
	uint8_t ser_oscore_pkt[40];
	uint32_t ser_oscore_pkt_len = sizeof(ser_oscore_pkt);
	memset(ser_coap_pkt_registration, 0, ser_coap_pkt_registration_len);
	memset(ser_oscore_pkt, 0, ser_oscore_pkt_len);

	struct o_coap_packet coap_pkt_registration = {
		.header = {
			.ver = 1,
			.type = TYPE_CON,
			.TKL = 1,
			.code = CODE_REQ_GET,
			.MID = 0x0
		},
		.token = token,
		.options_cnt = 2,
		.options = {
			    { .delta = 6,
			       .len = sizeof(observe_val),
			       .value = observe_val,
			       .option_number = OBSERVE },
				{ .delta = 5,
			       .len = sizeof(uri_path_val),
			       .value = uri_path_val,
			       .option_number = URI_PATH},/*E, opt num 11*/
                   },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	r = coap_serialize(&coap_pkt_registration, ser_coap_pkt_registration,
			   &ser_coap_pkt_registration_len);
	zassert_equal(
		r, ok,
		"Error in coap_serialize during registration packet serialization!");

	PRINT_ARRAY("CoAP observe registration", ser_coap_pkt_registration,
		    ser_coap_pkt_registration_len);

	r = coap2oscore(ser_coap_pkt_registration,
			ser_coap_pkt_registration_len, ser_oscore_pkt,
			&ser_oscore_pkt_len, &c_client);
	zassert_equal(r, ok, "Error in coap2oscore!");
	uint8_t EXPECTED_OSCORE_REGISTRATION[] = {
		0x41, 0x05, 0x00, 0x00, 0x4A, 0x61, 0x00, 0x32, 0x09,
		0x00, 0xFF, 0xAE, 0x58, 0x5E, 0x2E, 0x65, 0x89, 0x40,
		0xE6, 0xDB, 0xF4, 0xB7, 0x08, 0xB7, 0x93, 0x37, 0x03,
		0x41, 0x1E, 0x50, 0x8E, 0xEA, 0x79, 0x70
	};
	zassert_mem_equal__(&ser_oscore_pkt, EXPECTED_OSCORE_REGISTRATION,
			    sizeof(EXPECTED_OSCORE_REGISTRATION),
			    "coap2oscore failed");

	PRINT_ARRAY("OSCORE observe registration", ser_oscore_pkt,
		    ser_oscore_pkt_len);

	uint8_t ser_conv_coap_pkt[40];
	uint32_t ser_conv_coap_pkt_len = sizeof(ser_conv_coap_pkt);

	r = oscore2coap(ser_oscore_pkt, ser_oscore_pkt_len, ser_conv_coap_pkt,
			&ser_conv_coap_pkt_len, &c_server);
	zassert_equal(r, ok, "Error in oscore2coap!");
	/*check if we recovered the coap packet that the client sent*/
	zassert_mem_equal__(ser_coap_pkt_registration, ser_conv_coap_pkt,
			    ser_conv_coap_pkt_len, "oscore2coap failed");

	PRINT_ARRAY("Converted CoAP observe registration", ser_conv_coap_pkt,
		    ser_conv_coap_pkt_len);

	/*
	 *
	 *test the first notification (first response)
	 *
	 */

	PRINT_MSG("\n\n |<-----notification1----| \n\n");

	uint8_t ser_coap_pkt_notification1[40];
	uint32_t ser_coap_pkt_notification1_len =
		sizeof(ser_coap_pkt_notification1);
	uint8_t ser_oscore_pkt_notification1[40];
	uint32_t ser_oscore_pkt_notification1_len =
		sizeof(ser_oscore_pkt_notification1);
	memset(ser_coap_pkt_notification1, 0, ser_coap_pkt_notification1_len);
	memset(ser_oscore_pkt_notification1, 0,
	       ser_oscore_pkt_notification1_len);

	/*RFC7641: To provide an order among notifications for the client, the server
   	sets the value of the Observe Option in each notification to the 24
   	least significant bits of a strictly increasing sequence number.*/
	//uint32_t observe_sequence_number = 0;
	uint32_t val = 0;
	struct o_coap_packet coap_pkt_notification1 = {
		.header = { .ver = 1,
			    .type = TYPE_ACK,
			    .TKL = 1,
			    .code = CODE_RESP_CONTENT,
			    .MID = 0x0 },
		.token = token,
		.options_cnt = 1,
		.options = { { .delta = 6,
			       .len = 3, //take only the lower 24 bit
			       .value =
				       (uint8_t *)&val, //convert to network byte order
			       .option_number = OBSERVE } },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	r = coap_serialize(&coap_pkt_notification1, ser_coap_pkt_notification1,
			   &ser_coap_pkt_notification1_len);
	zassert_equal(
		r, ok,
		"Error in coap_serialize during notification1 packet serialization!");

	PRINT_ARRAY("CoAP observe notification1", ser_coap_pkt_notification1,
		    ser_coap_pkt_notification1_len);

	r = coap2oscore(ser_coap_pkt_notification1,
			ser_coap_pkt_notification1_len, ser_oscore_pkt,
			&ser_oscore_pkt_len, &c_server);
	zassert_equal(r, ok, "Error in coap2oscore!");
	uint8_t EXPECTED_OSCORE_NOTIFICATION1[] = {
		0x61, 0x45, 0x00, 0x00, 0x4A, 0x63, 0x00, 0x00,
		0x00, 0x33, 0x09, 0x00, 0x01, 0xFF, 0x4D, 0xD3,
		0x4F, 0x59, 0x4E, 0x54, 0x7B, 0x25, 0x0E, 0x1B
	};
	zassert_mem_equal__(&ser_oscore_pkt, EXPECTED_OSCORE_NOTIFICATION1,
			    sizeof(EXPECTED_OSCORE_NOTIFICATION1),
			    "coap2oscore failed");

	PRINT_ARRAY("OSCORE observe notification1", ser_oscore_pkt,
		    ser_oscore_pkt_len);

	ser_conv_coap_pkt_len = sizeof(ser_conv_coap_pkt);
	r = oscore2coap(ser_oscore_pkt, ser_oscore_pkt_len, ser_conv_coap_pkt,
			&ser_conv_coap_pkt_len, &c_client);

	zassert_equal(r, ok, "Error in oscore2coap!");
	uint8_t EXPECTED_CONVERTED_COAP[] = {
		0x61, 0x45, 0x00, 0x00, 0x4A, 0x60
	};
	zassert_mem_equal__(&ser_conv_coap_pkt, EXPECTED_CONVERTED_COAP,
			    sizeof(EXPECTED_CONVERTED_COAP),
			    "oscore2coap failed");

	PRINT_ARRAY("Converted CoAP observe notification", ser_conv_coap_pkt,
		    ser_conv_coap_pkt_len);

	/*try replay notification 1*/
	PRINT_MSG("Try to replay previous notification\n");
	r = oscore2coap(ser_oscore_pkt, ser_oscore_pkt_len, ser_conv_coap_pkt,
			&ser_conv_coap_pkt_len, &c_client);
	zassert_equal(r, oscore_replay_notification_protection_error,
		      "Error in oscore2coap!");
}

/**
 * @brief	This function test the behavior of a server and a client for contexts
 * 			stored in FLASH, after reboot of the server and the rejection of a replayed request.
 *
 *		   client				 				 		server
 *		  ---------			        				---------
 *			|                                   		|
 *		1)	|------request----------------------------->|
 *			|<-----response with ECHO option (ECHO1)----|
 *			|                                   		|
 *		2)	|------new request without ECHO opt-------->| 
 *			|<-----response with new ECHO option (ECHO2)|
 *			|              		            			|
 *		3)	|------request with old ECHO option-(ECHO1)>|
 * 			|<-----response with new ECHO option (ECHO3)|
 * 			|											|
 *		4)	|------request with ECHO option-(ECHO3)---->|
 * 			|<-----response-----------------------------|
 *			|											|
 *		5)	|------request----------------------------->|
 * 			|------replayed request----------X			| rejected message
 *
 * 			See as RFC8613 Appendix B1.2 and RFC9175
 * 
 * - 1) and 4) are represent the normal flow. 
 * - 2), 3) and 5) represent special cases.
 * 
 * 
 * 
 * 1) 	The client send a first request. The server responds with ECHO option. 
 *		This flow is mandatory for contexts restored from FLASH and should be executed after
 *		every reboot of the server. Then the client should send the ECHO option that it 
 *		received in the next request.
 *
 * 2)	The client sends a new request without an ECHO option. This may happen 
 * 		if for some reason the client did not received the first ECHO option.
 * 
 * 3)	The client responds with wrong option -- not ECHO2 but ECHO1. The 
 * 		client receives a new option ECHO3 from the server.
 * 
 * 4)	The client sends the expected ECHO option ECHO3
 * 5)	The client replays an request which gets detected.
 */
void t10_oscore_client_server_after_reboot(void)
{
	/*
	 *
	 * Initialize contexts for the client and server
	 *
	 */
	enum err r;
	struct context cc; //context of the client
	struct oscore_init_params params_client = get_default_params(NORMAL, RESTORED);
	r = oscore_context_init(&params_client, &cc);
	zassert_equal(r, ok, "Error in oscore_context_init for client");

	struct context cs; //context of the server
	struct oscore_init_params params_server = get_default_params(REVERSED, RESTORED);
	r = oscore_context_init(&params_server, &cs);
	zassert_equal(r, ok, "Error in oscore_context_init for server");

	/*coap and oscore buffers*/
	uint8_t coap_pkt[40];
	uint8_t oscore_pkt[60];
	uint8_t conv_coap_pkt[40];
	uint32_t coap_pkt_len;
	uint32_t oscore_pkt_len;
	uint32_t conv_coap_pkt_len;

	/*Expected OSCORE values*/
	const uint8_t OSCORE_REQ1[] = { 0x41, 0x02, 0x00, 0x00, 0x4A, 0x92, 0x09, 0x14, 0xFF, 0x61, 0x27, 0x10, 0x81, 0xAD, 0xF0, 0x0E, 0xEA, 0x55, 0xF1, 0x52, 0x39, 0x6C, 0xA3, 0x72, 0x46, 0x96, 0x73, 0xB2, 0x09, 0xF7 };

	const uint8_t OSCORE_RESP1[] = { 0x61, 0x44, 0x00, 0x00, 0x4A, 0x93, 0x09, 0x14, 0x01, 0xFF, 0xBC, 0xB9, 0x3C, 0xA6, 0x0E, 0xF7, 0x11, 0x52, 0x39, 0x45, 0x1B, 0xEA, 0x4C, 0x81, 0x90, 0xCA, 0x60, 0x38, 0x76, 0xD6, 0x09, 0xDE, 0x46 };

	const uint8_t OSCORE_RESP2[] = { 0x61, 0x44, 0x00, 0x00, 0x4A, 0x93, 0x09, 0x15, 0x01, 0xFF, 0x97, 0xA4, 0x25, 0x7B, 0x17, 0x39, 0xC0, 0x1D, 0x5E, 0x9D, 0xDA, 0x02, 0x74, 0xDB, 0xD4, 0xBF, 0xE6, 0x82, 0x18, 0x9B, 0x3B, 0xBF, 0x0E };

	const uint8_t OSCORE_REQ3[] = { 0x41, 0x02, 0x00, 0x00, 0x4B, 0x92, 0x09, 0x16, 0xFF, 0x8C, 0x2F, 0xED, 0xB3, 0xBB, 0xCD, 0xEE, 0x17, 0xB0, 0x12, 0x03, 0x95, 0x74, 0xD8, 0x08, 0x55, 0x40, 0x53, 0x82, 0x2B, 0x3C, 0x79, 0xA5, 0x1B, 0xCA, 0xFC, 0xC9, 0xD0, 0xC6, 0x35, 0x50, 0xDC, 0x5D, 0x1D, 0x13 };

	const uint8_t OSCORE_RESP3[] = { 0x61, 0x44, 0x00, 0x00, 0x4B, 0x93, 0x09, 0x16, 0x01, 0xFF, 0x9B, 0xE4, 0x04, 0x05, 0x9F, 0x1C, 0xCE, 0x6A, 0x43, 0x85, 0xD2, 0xD7, 0x12, 0x52, 0x49, 0xB2, 0x8A, 0xD7, 0xD5, 0x0A, 0x67, 0x09, 0x82 };

	const uint8_t OSCORE_REQ4[] = { 0x41, 0x02, 0x00, 0x00, 0x4B, 0x92, 0x09, 0x17, 0xFF, 0xCD, 0x4A, 0x87, 0x1E, 0xCD, 0xE0, 0x07, 0xD2, 0xCB, 0xF5, 0xC4, 0x76, 0x84, 0x1E, 0x4C, 0x94, 0x39, 0xCE, 0x82, 0x6F, 0x1A, 0xF6, 0xB4, 0xC1, 0x68, 0xE6, 0xB3, 0xBB, 0xDB, 0x8B, 0x84, 0x4F, 0xDE, 0x95, 0x94 };

	const uint8_t OSCORE_RESP4[] = { 0x61, 0x44, 0x00, 0x00, 0x4B, 0x90, 0xFF, 0x5E, 0x04, 0x3E, 0xD6, 0x11, 0x1F, 0xE7, 0xF7, 0x9D, 0x1E, 0x5F, 0x30, 0x27, 0x30 };

	/**********************************************************************/
	/*1)	|------request----------------------------->|		      */
	/*	|<-----response with ECHO option (ECHO1)----|		      */
	/**********************************************************************/
	/*
	 *
	 * First request
	 *
	 */
	PRINT_MSG("\n\n |------request----------------------------->| \n\n");
	uint8_t uri_path_val[] = { 't', 'e', 'm', 'p', 'e', 'r',
				   'a', 't', 'u', 'r', 'e' };
	uint8_t token[] = { 0x4a };

	struct o_coap_packet coap_pkt_req1 = {
		.header = {
			.ver = 1,
			.type = TYPE_CON,
			.TKL = 1,
			.code = CODE_REQ_GET,
			.MID = 0x0
		},
		.token = token,
		.options_cnt = 1,
		.options = {
                        { .delta = 11,
                        .len = sizeof(uri_path_val),
                        .value = uri_path_val,
                        .option_number = URI_PATH},/*E, opt num 11*/
                   },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	coap_pkt_len = sizeof(coap_pkt);
	r = coap_serialize(&coap_pkt_req1, coap_pkt, &coap_pkt_len);
	zassert_equal(r, ok, "req1 serialization failed!");

	PRINT_ARRAY("CoAP  req1", coap_pkt, coap_pkt_len);

	oscore_pkt_len = sizeof(oscore_pkt);
	r = coap2oscore(coap_pkt, coap_pkt_len, oscore_pkt, &oscore_pkt_len,
			&cc);
	zassert_equal(r, ok, "Error in coap2oscore!");
	PRINT_ARRAY("OSCORE req1", oscore_pkt, oscore_pkt_len);
	zassert_mem_equal__(oscore_pkt, OSCORE_REQ1, sizeof(OSCORE_REQ1),
			    "coap2oscore failed");

	conv_coap_pkt_len = sizeof(conv_coap_pkt);
	r = oscore2coap(oscore_pkt, oscore_pkt_len, conv_coap_pkt,
			&conv_coap_pkt_len, &cs);

	zassert_equal(r, first_request_after_reboot, "Error in oscore2coap!");

	/*
	*
	* Response with ECHO option
	*
	*
	*/
	PRINT_MSG("\n\n |<-----response with ECHO option (ECHO1)----|	 \n\n");

	/*Test first the rejection of CoAP packets without an echo option*/
	PRINT_MSG(
		"Try first supplying a CoAP message without an ECHO option\n");
	uint8_t COAP_RESP_WITHOUT_ECHO[] = { 0x61, 0x81, 0x00, 0x00, 0x4A };
	oscore_pkt_len = sizeof(oscore_pkt);
	r = coap2oscore(COAP_RESP_WITHOUT_ECHO, sizeof(COAP_RESP_WITHOUT_ECHO),
			oscore_pkt, &oscore_pkt_len, &cs);
	zassert_equal(r, no_echo_option, "Error in coap2oscore!");

	/* do it now the correct way -- with ECHO option*/
	uint8_t echo_opt_val1[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
				    0x06, 0x07, 0x08, 0x09, 0x10, 0x11 };

	struct o_coap_packet coap_pkt_resp1 = {
		.header = { .ver = 1,
			    .type = TYPE_ACK,
			    .TKL = 1,
			    .code = CODE_RESP_UNAUTHORIZED,
			    .MID = 0x0 },
		.token = token,
		.options_cnt = 1,
		.options = { { .delta = 252,
			       .len = sizeof(echo_opt_val1),
			       .value = echo_opt_val1,
			       .option_number = ECHO } },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	coap_pkt_len = sizeof(coap_pkt);
	r = coap_serialize(&coap_pkt_resp1, coap_pkt, &coap_pkt_len);
	zassert_equal(r, ok, "Error in coap_serialize");

	oscore_pkt_len = sizeof(oscore_pkt);
	r = coap2oscore(coap_pkt, coap_pkt_len, oscore_pkt, &oscore_pkt_len,
			&cs);
	zassert_equal(r, ok, "Error in coap2oscore!");

	PRINT_ARRAY("OSCORE resp1", oscore_pkt, oscore_pkt_len);
	zassert_mem_equal__(oscore_pkt, OSCORE_RESP1, sizeof(OSCORE_RESP1),
			    "coap2oscore failed");

	conv_coap_pkt_len = sizeof(conv_coap_pkt);
	r = oscore2coap(oscore_pkt, oscore_pkt_len, conv_coap_pkt,
			&conv_coap_pkt_len, &cc);

	zassert_equal(r, ok, "Error in oscore2coap!");
	zassert_mem_equal__(conv_coap_pkt, coap_pkt, conv_coap_pkt_len,
			    "oscore2coap failed");

	/**************************************************************************/
	/* 		2)	|------new request without ECHO opt-------->| 				  */
	/*			|<-----response with new ECHO option (ECHO2)|			      */
	/**************************************************************************/
	/*
	*
	* Request
	*
	*/
	PRINT_MSG("\n\n|------new request without ECHO opt-------->| \n\n");
	uint8_t COAP_REQ_WITHOUT_ECHO[] = { 0x41, 0x01, 0x00, 0x00, 0x4A };

	oscore_pkt_len = sizeof(oscore_pkt);
	r = coap2oscore(COAP_REQ_WITHOUT_ECHO, sizeof(COAP_REQ_WITHOUT_ECHO),
			oscore_pkt, &oscore_pkt_len, &cc);
	zassert_equal(r, ok, "Error in coap2oscore!");

	PRINT_ARRAY("OSCORE req2", oscore_pkt, oscore_pkt_len);

	conv_coap_pkt_len = sizeof(conv_coap_pkt);
	r = oscore2coap(oscore_pkt, oscore_pkt_len, conv_coap_pkt,
			&conv_coap_pkt_len, &cs);

	zassert_equal(r, echo_validation_failed, "Error in oscore2coap!");

	/*
	*
	* Response
	*
	*/
	PRINT_MSG("\n\n|<-----response with new ECHO option (ECHO2)|\n\n");
	uint8_t echo_opt_val2[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x10, 0x22
	}; /*last byte is different*/
	struct o_coap_packet coap_pkt_resp2 = {
		.header = { .ver = 1,
			    .type = TYPE_ACK,
			    .TKL = 1,
			    .code = CODE_RESP_UNAUTHORIZED,
			    .MID = 0x0 },
		.token = token,
		.options_cnt = 1,
		.options = { { .delta = 252,
			       .len = sizeof(echo_opt_val2),
			       .value = echo_opt_val2,
			       .option_number = ECHO } },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	coap_pkt_len = sizeof(coap_pkt);
	r = coap_serialize(&coap_pkt_resp2, coap_pkt, &coap_pkt_len);
	zassert_equal(r, ok, "Error in coap_serialize!");

	oscore_pkt_len = sizeof(oscore_pkt);
	r = coap2oscore(coap_pkt, coap_pkt_len, oscore_pkt, &oscore_pkt_len,
			&cs);
	zassert_equal(r, ok, "Error in coap2oscore!");

	PRINT_ARRAY("OSCORE resp2", oscore_pkt, oscore_pkt_len);
	zassert_mem_equal__(oscore_pkt, OSCORE_RESP2, oscore_pkt_len,
			    "coap2oscore failed");

	conv_coap_pkt_len = sizeof(conv_coap_pkt);
	r = oscore2coap(oscore_pkt, oscore_pkt_len, conv_coap_pkt,
			&conv_coap_pkt_len, &cc);

	zassert_equal(r, ok, "Error in oscore2coap!");

	zassert_mem_equal__(conv_coap_pkt, coap_pkt, coap_pkt_len,
			    "oscore2coap failed");

	/**************************************************************************/
	/*		3)	|------request with old ECHO option-(ECHO1)>|*/
	/* 			|<-----response with new ECHO option (ECHO3)|*/
	/**************************************************************************/
	/*
	 *
	 * Request with old ECHO option-(ECHO1)
	 *
	 */
	PRINT_MSG("\n\n |-------request with old ECHO option-(ECHO1)>|| \n\n");
	token[0] = 0x4b;

	struct o_coap_packet coap_pkt_req2 = {
		.header = {
			.ver = 1,
			.type = TYPE_CON,
			.TKL = 1,
			.code = CODE_REQ_GET,
			.MID = 0x0
		},
		.token = token,
		.options_cnt = 2,
		.options = {
					    {
							.delta = 11,
	                    	.len = sizeof(uri_path_val),
	                    	.value = uri_path_val,
	                    	.option_number = URI_PATH},/*E, opt num 11*/
	                    {
							.delta = 241,
	                    	.len = sizeof(echo_opt_val1),
	                    	.value = echo_opt_val1,
	                    	.option_number = ECHO},/*ECHO, opt num 252*/
	               },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	coap_pkt_len = sizeof(coap_pkt);
	r = coap_serialize(&coap_pkt_req2, coap_pkt, &coap_pkt_len);
	zassert_equal(r, ok, "Error in coap_serialize !");

	oscore_pkt_len = sizeof(oscore_pkt);
	r = coap2oscore(coap_pkt, coap_pkt_len, oscore_pkt, &oscore_pkt_len,
			&cc);
	zassert_equal(r, ok, "Error in coap2oscore!");
	
	PRINT_ARRAY("OSCORE req3", oscore_pkt, oscore_pkt_len);
	zassert_mem_equal__(oscore_pkt, OSCORE_REQ3, oscore_pkt_len,
			    "coap2oscore failed");

	conv_coap_pkt_len = sizeof(conv_coap_pkt);
	r = oscore2coap(oscore_pkt, oscore_pkt_len, conv_coap_pkt,
			&conv_coap_pkt_len, &cs);

	zassert_equal(r, echo_validation_failed, "Error in oscore2coap!");

	/*
	 *
	 * Response option ECHO3
	 *
	 */
	PRINT_MSG("\n\n|<-----response with new ECHO option (ECHO2)|\n\n");
	uint8_t echo_opt_val3[] = {
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
		0x06, 0x07, 0x08, 0x09, 0x10, 0x33
	}; /*last byte is different*/
	struct o_coap_packet coap_pkt_resp3 = {
		.header = { .ver = 1,
			    .type = TYPE_ACK,
			    .TKL = 1,
			    .code = CODE_RESP_UNAUTHORIZED,
			    .MID = 0x0 },
		.token = token,
		.options_cnt = 1,
		.options = { { .delta = 252,
			       .len = sizeof(echo_opt_val3),
			       .value = echo_opt_val3,
			       .option_number = ECHO } },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	coap_pkt_len = sizeof(coap_pkt);
	r = coap_serialize(&coap_pkt_resp3, coap_pkt, &coap_pkt_len);
	zassert_equal(r, ok, "Error in coap_serialize!");

	oscore_pkt_len = sizeof(oscore_pkt);
	r = coap2oscore(coap_pkt, coap_pkt_len, oscore_pkt, &oscore_pkt_len,
			&cs);
	zassert_equal(r, ok, "Error in coap2oscore!");

	PRINT_ARRAY("OSCORE resp3", oscore_pkt, oscore_pkt_len);
	zassert_mem_equal__(oscore_pkt, OSCORE_RESP3, oscore_pkt_len,
			    "coap2oscore failed");

	conv_coap_pkt_len = sizeof(conv_coap_pkt);
	r = oscore2coap(oscore_pkt, oscore_pkt_len, conv_coap_pkt,
			&conv_coap_pkt_len, &cc);

	zassert_equal(r, ok, "Error in oscore2coap!");

	zassert_mem_equal__(conv_coap_pkt, coap_pkt, coap_pkt_len,
			    "oscore2coap failed");

	/**************************************************************************/
	/*		4)	|------request with ECHO option-(ECHO3)---->|*/
	/* 			|<-----response-----------------------------|*/
	/**************************************************************************/

	/*
	 *
	 * Request with ECHO option
	 *
	 */
	PRINT_MSG("\n\n |------request with ECHO option-(ECHO3)---->| \n\n");
	struct o_coap_packet coap_pkt_req4 = {
		.header = {
			.ver = 1,
			.type = TYPE_CON,
			.TKL = 1,
			.code = CODE_REQ_GET,
			.MID = 0x0
		},
		.token = token,
		.options_cnt = 2,
		.options = {
					    {
							.delta = 11,
	                    	.len = sizeof(uri_path_val),
	                    	.value = uri_path_val,
	                    	.option_number = URI_PATH},/*E, opt num 11*/
	                    {
							.delta = 241,
	                    	.len = sizeof(echo_opt_val3),
	                    	.value = echo_opt_val3,
	                    	.option_number = ECHO},/*ECHO, opt num 252*/
	               },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	coap_pkt_len = sizeof(coap_pkt);
	r = coap_serialize(&coap_pkt_req4, coap_pkt, &coap_pkt_len);
	zassert_equal(r, ok, "Error in coap_serialize!");

	oscore_pkt_len = sizeof(oscore_pkt);
	r = coap2oscore(coap_pkt, coap_pkt_len, oscore_pkt, &oscore_pkt_len,
			&cc);
	zassert_equal(r, ok, "Error in coap2oscore!");

	PRINT_ARRAY("OSCORE req4", oscore_pkt, oscore_pkt_len);
	zassert_mem_equal__(oscore_pkt, OSCORE_REQ4, oscore_pkt_len,
			    "coap2oscore failed");

	conv_coap_pkt_len = sizeof(conv_coap_pkt);
	r = oscore2coap(oscore_pkt, oscore_pkt_len, conv_coap_pkt,
			&conv_coap_pkt_len, &cs);

	zassert_equal(r, 0, "Error in oscore2coap!");
	zassert_mem_equal__(conv_coap_pkt, coap_pkt, coap_pkt_len,
			    "oscore2coap failed");

	/*
	 *
	 * Normal response
	 *
	 */
	PRINT_MSG("\n\n |<------response2 ----| \n\n");
	uint8_t payload[] = { 0xde, 0xad, 0xbe, 0xaf };

	struct o_coap_packet coap_pkt_resp4 = {
		.header = { .ver = 1,
			    .type = TYPE_ACK,
			    .TKL = 1,
			    .code = CODE_RESP_CONTENT,
			    .MID = 0x0 },
		.token = token,
		.options_cnt = 0,
		.options = {},
		.payload.len = sizeof(payload),
		.payload.ptr = payload,
	};

	coap_pkt_len = sizeof(coap_pkt);
	r = coap_serialize(&coap_pkt_resp4, coap_pkt, &coap_pkt_len);
	zassert_equal(r, ok, "Error in coap_serialize !");

	oscore_pkt_len = sizeof(oscore_pkt);
	r = coap2oscore(coap_pkt, coap_pkt_len, oscore_pkt, &oscore_pkt_len,
			&cs);
	zassert_equal(r, ok, "Error in coap2oscore!");

	PRINT_ARRAY("OSCORE resp4", oscore_pkt, oscore_pkt_len);
	zassert_mem_equal__(oscore_pkt, OSCORE_RESP4, oscore_pkt_len,
			    "coap2oscore failed");

	conv_coap_pkt_len = sizeof(conv_coap_pkt);
	r = oscore2coap(oscore_pkt, oscore_pkt_len, conv_coap_pkt,
			&conv_coap_pkt_len, &cc);

	zassert_equal(r, ok, "Error in oscore2coap!");
	zassert_mem_equal__(conv_coap_pkt, coap_pkt, coap_pkt_len,
			    "oscore2coap failed");

	/**************************************************************************/
	/*		5)	|------request----------------------------->|				  */
	/* 			| -- -- --replayed request-- -- -- -- --X   | rejected message*/
	/**************************************************************************/

	/*
	 *
	 * Test replay protection on the server side
	 *
	 *
	*/
	PRINT_MSG(
		"\n\n |------ regular request (to be replayed later)---->| \n\n");
	token[0] = 0x4a;

	struct o_coap_packet coap_pkt_req5 = {
		.header = {
			.ver = 1,
			.type = TYPE_CON,
			.TKL = 1,
			.code = CODE_REQ_GET,
			.MID = 0x0
		},
		.token = token,
		.options_cnt = 1,
		.options = {
	                    { .delta = 11,
	                    .len = sizeof(uri_path_val),
	                    .value = uri_path_val,
	                    .option_number = URI_PATH},/*E, opt num 11*/
	               },
		.payload.len = 0,
		.payload.ptr = NULL,
	};

	coap_pkt_len = sizeof(coap_pkt);
	r = coap_serialize(&coap_pkt_req5, coap_pkt, &coap_pkt_len);
	zassert_equal(r, ok, "Error in coap_serialize!");

	oscore_pkt_len = sizeof(oscore_pkt);
	r = coap2oscore(coap_pkt, coap_pkt_len, oscore_pkt, &oscore_pkt_len,
			&cc);
	zassert_equal(r, ok, "Error in coap2oscore!");

	conv_coap_pkt_len = sizeof(conv_coap_pkt);
	r = oscore2coap(oscore_pkt, oscore_pkt_len, conv_coap_pkt,
			&conv_coap_pkt_len, &cs);
	zassert_equal(r, ok, "Error in oscore2coap!");

	/*try to replay the request*/
	r = oscore2coap(oscore_pkt, oscore_pkt_len, conv_coap_pkt,
			&conv_coap_pkt_len, &cs);

	zassert_equal(r, oscore_replay_window_protection_error,
		      "Error in oscore2coap!");
}

/**
 * Test 11:
 * According to RFC8613 p. 7.2.1, endpoint must not process any more message after reaching its final SSN value.
 */
void t11_oscore_ssn_overflow_protection(void)
{
	enum err result;
	struct context security_context;
	struct oscore_init_params params = get_default_params(NORMAL, RESTORED);

	uint8_t buf_oscore[256];
	uint32_t buf_oscore_len = sizeof(buf_oscore);
	uint8_t buf_coap[256];
	uint32_t buf_coap_len = sizeof(buf_coap);

	result = oscore_context_init(&params, &security_context);
	zassert_equal(result, ok, "Error in oscore_context_init");

	/* mimic reaching final value of SSN */
	security_context.sc.ssn = OSCORE_SSN_OVERFLOW_VALUE;

	/* test SSN overflow protection in coap2oscore */
	result = coap2oscore((uint8_t *)T1__COAP_REQ, T1__COAP_REQ_LEN,
			(uint8_t *)&buf_oscore, &buf_oscore_len, &security_context);
	zassert_equal(result, oscore_ssn_overflow, "SSN overflow not detected in coap2oscore");

	/* test SSN overflow protection in oscore2coap */
	result = oscore2coap((uint8_t *)T1__OSCORE_RESP, T1__OSCORE_RESP_LEN,
			(uint8_t *)&buf_coap, &buf_coap_len, &security_context);
	zassert_equal(result, oscore_ssn_overflow, "SSN overflow not detected in oscore2coap");
}
