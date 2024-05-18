/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdio.h>
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include <edhoc.h>
#include "txrx_wrapper.h"
#include "edhoc_test_vectors_rfc9529.h"

volatile uint8_t msg_cnt = 1;

enum err tx_fkt(void *sock, struct byte_array *data)
{
	switch (msg_cnt) {
	case 1:
		zassert_mem_equal__(data->ptr, T1_RFC9529__MESSAGE_1, data->len,
				    "wrong message1");
		zassert_equal(data->len, T1_RFC9529__MESSAGE_1_LEN,
			      "wrong message1 length");
		break;
	case 2:
		zassert_mem_equal__(data->ptr, T1_RFC9529__MESSAGE_2, data->len,
				    "wrong message2");
		zassert_equal(data->len, T1_RFC9529__MESSAGE_2_LEN,
			      "wrong message1 length");
		break;
	case 3:
		zassert_mem_equal__(data->ptr, T1_RFC9529__MESSAGE_3, data->len,
				    "wrong message3");
		zassert_equal(data->len, T1_RFC9529__MESSAGE_3_LEN,
			      "wrong message1 length");
		break;
	case 4:
		zassert_mem_equal__(data->ptr, T1_RFC9529__MESSAGE_4, data->len,
				    "wrong message4");
		zassert_equal(data->len, T1_RFC9529__MESSAGE_4_LEN,
			      "wrong message1 length");
		break;

	default:
		break;
	}

	msg_cnt++;
	return ok;
}

enum err rx_fkt(void *sock, struct byte_array *data)
{
	switch (msg_cnt) {
	case 1:

		TRY(_memcpy_s(data->ptr, data->len, T1_RFC9529__MESSAGE_1,
			      T1_RFC9529__MESSAGE_1_LEN));
		data->len = T1_RFC9529__MESSAGE_1_LEN;
		break;
	case 2:
		TRY(_memcpy_s(data->ptr, data->len, T1_RFC9529__MESSAGE_2,
			      T1_RFC9529__MESSAGE_2_LEN));
		data->len = T1_RFC9529__MESSAGE_2_LEN;
		break;
	case 3:
		TRY(_memcpy_s(data->ptr, data->len, T1_RFC9529__MESSAGE_3,
			      T1_RFC9529__MESSAGE_3_LEN));
		data->len = T1_RFC9529__MESSAGE_3_LEN;
		break;
	case 4:
		TRY(_memcpy_s(data->ptr, data->len, T1_RFC9529__MESSAGE_4,
			      T1_RFC9529__MESSAGE_4_LEN));
		data->len = T1_RFC9529__MESSAGE_4_LEN;
		break;

	default:
		break;
	}

	msg_cnt++;
	return ok;
}

enum err ead_fkt(void *params, struct byte_array *ead13)
{
	return ok;
}

void test_edhoc_initiator_x509_x5t_rfc9529(void)
{
	enum err r;
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	uint8_t I_PRK_out_buf[32];
	struct byte_array I_PRK_out = { .ptr = I_PRK_out_buf,
					.len = sizeof(I_PRK_out_buf) };

	uint8_t I_err_msg_buf[0];
	struct byte_array I_err_msg = { .ptr = I_err_msg_buf,
					.len = sizeof(I_err_msg_buf) };

	c_i.sock = NULL;
	c_i.c_i.len = T1_RFC9529__C_I_LEN;
	c_i.c_i.ptr = (uint8_t *)T1_RFC9529__C_I;
	c_i.method = (enum method_type)T1_RFC9529__METHOD;
	c_i.suites_i.len = T1_RFC9529__SUITES_I_LEN;
	c_i.suites_i.ptr = (uint8_t *)T1_RFC9529__SUITES_I;
	c_i.ead_1.len = 0;
	c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0;
	c_i.ead_3.ptr = NULL;
	c_i.id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN;
	c_i.id_cred_i.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	c_i.cred_i.len = T1_RFC9529__CRED_I_LEN;
	c_i.cred_i.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	c_i.g_x.len = T1_RFC9529__G_X_LEN;
	c_i.g_x.ptr = (uint8_t *)T1_RFC9529__G_X;
	c_i.x.len = T1_RFC9529__X_LEN;
	c_i.x.ptr = (uint8_t *)T1_RFC9529__X;
	c_i.g_i.len = 0;
	c_i.g_i.ptr = NULL;
	c_i.i.len = 0;
	c_i.i.ptr = NULL;
	c_i.sk_i.len = T1_RFC9529__SK_I_LEN;
	c_i.sk_i.ptr = (uint8_t *)T1_RFC9529__SK_I;
	c_i.pk_i.len = T1_RFC9529__PK_I_LEN;
	c_i.pk_i.ptr = (uint8_t *)T1_RFC9529__PK_I;

	cred_r.id_cred.len = T1_RFC9529__ID_CRED_R_LEN;
	cred_r.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	cred_r.cred.len = T1_RFC9529__CRED_R_LEN;
	cred_r.cred.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	cred_r.g.len = 0;
	cred_r.g.ptr = NULL;
	cred_r.pk.len = T1_RFC9529__PK_R_LEN;
	cred_r.pk.ptr = (uint8_t *)T1_RFC9529__PK_R;
	cred_r.ca.len = 0;
	cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0;
	cred_r.ca_pk.ptr = NULL;

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

	r = edhoc_initiator_run(&c_i, &cred_r_array, &I_err_msg, &I_PRK_out,
				tx_fkt, rx_fkt, ead_fkt);

	zassert_mem_equal__(I_PRK_out.ptr, T1_RFC9529__PRK_out, I_PRK_out.len,
			    "wrong PRK_out");

	msg_cnt = 1;
}

void test_edhoc_responder_x509_x5t_rfc9529(void)
{
	enum err r;
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	uint8_t R_PRK_out_buf[32];
	struct byte_array R_PRK_out = { .ptr = R_PRK_out_buf,
					.len = sizeof(R_PRK_out_buf) };

	uint8_t R_err_msg_buf[0];
	struct byte_array R_err_msg = { .ptr = R_err_msg_buf,
					.len = sizeof(R_err_msg_buf) };

	c_r.sock = NULL;
	c_r.c_r.ptr = (uint8_t *)T1_RFC9529__C_R;
	c_r.c_r.len = T1_RFC9529__C_R_LEN;
	c_r.suites_r.len = T1_RFC9529__SUITES_R_LEN;
	c_r.suites_r.ptr = (uint8_t *)T1_RFC9529__SUITES_R;
	c_r.ead_2.len = 0;
	c_r.ead_2.ptr = NULL;
	c_r.ead_4.len = 0;
	c_r.ead_4.ptr = NULL;
	c_r.id_cred_r.len = T1_RFC9529__ID_CRED_R_LEN;
	c_r.id_cred_r.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	c_r.cred_r.len = T1_RFC9529__CRED_R_LEN;
	c_r.cred_r.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	c_r.g_y.len = T1_RFC9529__G_Y_LEN;
	c_r.g_y.ptr = (uint8_t *)T1_RFC9529__G_Y;
	c_r.y.len = T1_RFC9529__Y_LEN;
	c_r.y.ptr = (uint8_t *)T1_RFC9529__Y;
	c_r.g_r.len = 0;
	c_r.g_r.ptr = NULL;
	c_r.r.len = 0;
	c_r.r.ptr = NULL;
	c_r.sk_r.len = T1_RFC9529__SK_R_LEN;
	c_r.sk_r.ptr = (uint8_t *)T1_RFC9529__SK_R;
	c_r.pk_r.len = T1_RFC9529__PK_R_LEN;
	c_r.pk_r.ptr = (uint8_t *)T1_RFC9529__PK_R;

	cred_i.id_cred.len = T1_RFC9529__ID_CRED_I_LEN;
	cred_i.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	cred_i.cred.len = T1_RFC9529__CRED_I_LEN;
	cred_i.cred.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	cred_i.g.len = 0;
	cred_i.g.ptr = NULL;
	cred_i.pk.len = T1_RFC9529__PK_I_LEN;
	cred_i.pk.ptr = (uint8_t *)T1_RFC9529__PK_I;
	cred_i.ca.len = 0;
	cred_i.ca.ptr = NULL;
	cred_i.ca_pk.len = 0;
	cred_i.ca_pk.ptr = NULL;

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };

	r = edhoc_responder_run(&c_r, &cred_i_array, &R_err_msg, &R_PRK_out,
				tx_fkt, rx_fkt, ead_fkt);

	zassert_mem_equal__(R_PRK_out.ptr, T1_RFC9529__PRK_out, R_PRK_out.len,
			    "wrong PRK_out");

	msg_cnt = 1;
}
