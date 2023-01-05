/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include <zephyr/zephyr.h>
#include <zephyr/ztest.h>

#include <edhoc.h>

#include "edhoc_test_vectors_p256_v15.h"

uint8_t I_prk_exporter[32];
uint8_t I_master_secret[16];
uint8_t I_master_salt[8];
uint8_t I_PRK_out[PRK_DEFAULT_SIZE];
uint8_t I_err_msg[ERR_MSG_DEFAULT_SIZE];
uint32_t I_err_msg_len = sizeof(I_err_msg);
uint8_t I_ad_2[AD_DEFAULT_SIZE];
uint32_t I_ad_2_len = sizeof(I_ad_2);
uint8_t I_ad_4[AD_DEFAULT_SIZE];
uint32_t I_ad_4_len = sizeof(I_ad_4);

uint8_t R_prk_exporter[32];
uint8_t R_master_secret[16];
uint8_t R_master_salt[8];
uint8_t R_PRK_out[PRK_DEFAULT_SIZE];
uint8_t R_err_msg[ERR_MSG_DEFAULT_SIZE];
uint32_t R_err_msg_len = sizeof(R_err_msg);
uint8_t R_ad_1[AD_DEFAULT_SIZE];
uint32_t R_ad_1_len = sizeof(R_ad_1);
uint8_t R_ad_3[AD_DEFAULT_SIZE];
uint32_t R_ad_3_len = sizeof(R_ad_3);

/* size of stack area used by each thread */
#define STACKSIZE 1024
/* scheduling priority used by each thread */
#define PRIORITY 7
K_THREAD_STACK_DEFINE(thread_initiator_stack_area, STACKSIZE);
static struct k_thread thread_initiator_data;
K_THREAD_STACK_DEFINE(thread_responder_stack_area, STACKSIZE);
static struct k_thread thread_responder_data;

/*semaphores*/
K_SEM_DEFINE(tx_initiator_completed, 0, 1);
K_SEM_DEFINE(tx_responder_completed, 0, 1);

/*message exchange buffer*/
uint8_t msg_exchange_buf[1024];
uint32_t msg_exchange_buf_len = sizeof(msg_exchange_buf);

void semaphore_give(struct k_sem *sem)
{
	k_sem_give(sem);
}

enum err semaphore_take(struct k_sem *sem, uint8_t *data, uint32_t *data_len)
{
	if (k_sem_take(sem, K_MSEC(50)) != 0) {
		PRINT_MSG("Cannot receive a message!\n");
	} else {
		if (msg_exchange_buf_len > *data_len) {
			return buffer_to_small;
		} else {
			memcpy(data, msg_exchange_buf, *data_len);
			*data_len = msg_exchange_buf_len;
		}
	}
	return ok;
}

enum err copy_message(uint8_t *data, uint32_t data_len)
{
	if (data_len > sizeof(msg_exchange_buf)) {
		PRINT_MSG("msg_exchange_buf to small\n");
		return buffer_to_small;
	} else {
		memcpy(msg_exchange_buf, data, data_len);
		msg_exchange_buf_len = data_len;
	}
	return ok;
}

enum err tx_initiator(void *sock, uint8_t *data, uint32_t data_len)
{
	enum err r = copy_message(data, data_len);
	if (r != ok) {
		return r;
	}
	semaphore_give(&tx_initiator_completed);
	return ok;
}

enum err tx_responder(void *sock, uint8_t *data, uint32_t data_len)
{
	enum err r = copy_message(data, data_len);
	if (r != ok) {
		return r;
	}
	semaphore_give(&tx_responder_completed);
	return ok;
}

enum err rx_initiator(void *sock, uint8_t *data, uint32_t *data_len)
{
	return semaphore_take(&tx_responder_completed, data, data_len);
}
enum err rx_responder(void *sock, uint8_t *data, uint32_t *data_len)
{
	return semaphore_take(&tx_initiator_completed, data, data_len);
}

/**
 * @brief			A thread in which an Initiator instance is executed
 * 
 * @param vec_num 	Test vector number
 * @param dummy2 	unused
 * @param dummy3 	unused
 */
void thread_initiator(void *vec_num, void *dummy2, void *dummy3)
{
	ARG_UNUSED(dummy2);
	ARG_UNUSED(dummy3);

	PRINT_MSG("Initiator thread started!\n");

	uint8_t vec_num_i = *((int *)vec_num) - 1;
	enum err r;

	uint16_t cred_num = 1;
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	c_i.msg4 = true;
	c_i.sock = NULL;
	c_i.c_i.len = test_vectors[vec_num_i].c_i_len;
	c_i.c_i.ptr = (uint8_t *)test_vectors[vec_num_i].c_i;
	c_i.method = (enum method_type) * test_vectors[vec_num_i].method;
	c_i.suites_i.len = test_vectors[vec_num_i].SUITES_I_len;
	c_i.suites_i.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_I;
	c_i.ead_1.len = test_vectors[vec_num_i].ead_1_len;
	c_i.ead_1.ptr = (uint8_t *)test_vectors[vec_num_i].ead_1;
	c_i.ead_3.len = test_vectors[vec_num_i].ead_3_len;
	c_i.ead_3.ptr = (uint8_t *)test_vectors[vec_num_i].ead_3;
	c_i.id_cred_i.len = test_vectors[vec_num_i].id_cred_i_len;
	c_i.id_cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	c_i.cred_i.len = test_vectors[vec_num_i].cred_i_len;
	c_i.cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	c_i.g_x.len = test_vectors[vec_num_i].g_x_raw_len;
	c_i.g_x.ptr = (uint8_t *)test_vectors[vec_num_i].g_x_raw;
	c_i.x.len = test_vectors[vec_num_i].x_raw_len;
	c_i.x.ptr = (uint8_t *)test_vectors[vec_num_i].x_raw;
	c_i.g_i.len = test_vectors[vec_num_i].g_i_raw_len;
	c_i.g_i.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	c_i.i.len = test_vectors[vec_num_i].i_raw_len;
	c_i.i.ptr = (uint8_t *)test_vectors[vec_num_i].i_raw;
	c_i.sk_i.len = test_vectors[vec_num_i].sk_i_raw_len;
	c_i.sk_i.ptr = (uint8_t *)test_vectors[vec_num_i].sk_i_raw;
	c_i.pk_i.len = test_vectors[vec_num_i].pk_i_raw_len;
	c_i.pk_i.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;

	cred_r.id_cred.len = test_vectors[vec_num_i].id_cred_r_len;
	cred_r.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	cred_r.cred.len = test_vectors[vec_num_i].cred_r_len;
	cred_r.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	cred_r.g.len = test_vectors[vec_num_i].g_r_raw_len;
	cred_r.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	cred_r.pk.len = test_vectors[vec_num_i].pk_r_raw_len;
	cred_r.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;
	cred_r.ca.len = test_vectors[vec_num_i].ca_r_len;
	cred_r.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r;
	cred_r.ca_pk.len = test_vectors[vec_num_i].ca_r_pk_len;
	cred_r.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r_pk;

	r = edhoc_initiator_run(&c_i, &cred_r, cred_num, I_err_msg,
				&I_err_msg_len, I_ad_2, &I_ad_2_len, I_ad_4,
				&I_ad_4_len, I_PRK_out, sizeof(I_PRK_out),
				tx_initiator, rx_initiator);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("I_PRK_out", I_PRK_out, sizeof(I_PRK_out));

	r = prk_out2exporter(SHA_256, I_PRK_out, sizeof(I_PRK_out),
				 I_prk_exporter);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("I_prk_exporter", I_prk_exporter, sizeof(I_prk_exporter));

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, I_prk_exporter,
			   sizeof(I_prk_exporter), I_master_secret,
			   sizeof(I_master_secret));
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Secret", I_master_secret,
			sizeof(I_master_secret));

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, I_prk_exporter,
			   sizeof(I_prk_exporter), I_master_salt,
			   sizeof(I_master_salt));
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Salt", I_master_salt, sizeof(I_master_salt));
	return;
end:
	PRINTF("An error has occurred. Error code: %d\n", r);
}

/**
 * @brief			A thread in which a Responder instance is executed
 * 
 * @param vec_num 	Test vector number
 * @param dummy2 	unused
 * @param dummy3 	unused
 */
void thread_responder(void *vec_num, void *dummy2, void *dummy3)
{
	ARG_UNUSED(dummy2);
	ARG_UNUSED(dummy3);

	PRINT_MSG("Responder thread started!\n");
	enum err r;
	uint8_t vec_num_i = *((int *)vec_num) - 1;

	/* test vector inputs */
	uint16_t cred_num = 1;
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	c_r.msg4 = true;
	c_r.sock = NULL;
	c_r.c_r.ptr = (uint8_t *)test_vectors[vec_num_i].c_r;
	c_r.c_r.len = test_vectors[vec_num_i].c_r_len;
	c_r.suites_r.len = test_vectors[vec_num_i].SUITES_R_len;
	c_r.suites_r.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_R;
	c_r.ead_2.len = test_vectors[vec_num_i].ead_2_len;
	c_r.ead_2.ptr = (uint8_t *)test_vectors[vec_num_i].ead_2;
	c_r.ead_4.len = test_vectors[vec_num_i].ead_4_len;
	c_r.ead_4.ptr = (uint8_t *)test_vectors[vec_num_i].ead_4;
	c_r.id_cred_r.len = test_vectors[vec_num_i].id_cred_r_len;
	c_r.id_cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	c_r.cred_r.len = test_vectors[vec_num_i].cred_r_len;
	c_r.cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	c_r.g_y.len = test_vectors[vec_num_i].g_y_raw_len;
	c_r.g_y.ptr = (uint8_t *)test_vectors[vec_num_i].g_y_raw;
	c_r.y.len = test_vectors[vec_num_i].y_raw_len;
	c_r.y.ptr = (uint8_t *)test_vectors[vec_num_i].y_raw;
	c_r.g_r.len = test_vectors[vec_num_i].g_r_raw_len;
	c_r.g_r.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	c_r.r.len = test_vectors[vec_num_i].r_raw_len;
	c_r.r.ptr = (uint8_t *)test_vectors[vec_num_i].r_raw;
	c_r.sk_r.len = test_vectors[vec_num_i].sk_r_raw_len;
	c_r.sk_r.ptr = (uint8_t *)test_vectors[vec_num_i].sk_r_raw;
	c_r.pk_r.len = test_vectors[vec_num_i].pk_r_raw_len;
	c_r.pk_r.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;

	cred_i.id_cred.len = test_vectors[vec_num_i].id_cred_i_len;
	cred_i.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	cred_i.cred.len = test_vectors[vec_num_i].cred_i_len;
	cred_i.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	cred_i.g.len = test_vectors[vec_num_i].g_i_raw_len;
	cred_i.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	cred_i.pk.len = test_vectors[vec_num_i].pk_i_raw_len;
	cred_i.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;
	cred_i.ca.len = test_vectors[vec_num_i].ca_i_len;
	cred_i.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i;
	cred_i.ca_pk.len = test_vectors[vec_num_i].ca_i_pk_len;
	cred_i.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i_pk;

	r = edhoc_responder_run(&c_r, &cred_i, cred_num, R_err_msg,
				&R_err_msg_len, (uint8_t *)&R_ad_1, &R_ad_1_len,
				(uint8_t *)&R_ad_3, &R_ad_3_len, R_PRK_out,
				sizeof(R_PRK_out), tx_responder, rx_responder);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("R_PRK_out", R_PRK_out, sizeof(R_PRK_out));

	r = prk_out2exporter(SHA_256, R_PRK_out, sizeof(R_PRK_out),
				 R_prk_exporter);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("R_prk_exporter", R_prk_exporter, sizeof(R_prk_exporter));

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, R_prk_exporter,
			   sizeof(R_prk_exporter), R_master_secret,
			   sizeof(R_master_secret));
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Secret", R_master_secret,
			sizeof(R_master_secret));

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, R_prk_exporter,
			   sizeof(R_prk_exporter), R_master_salt,
			   sizeof(R_master_salt));
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Salt", R_master_salt, sizeof(R_master_salt));
	return;
end:
	PRINTF("An error has occurred. Error code: %d\n", r);
}

void test_initiator_responder_interaction(uint8_t vec_num)
{
	PRINT_MSG("start initiator_responder_interaction\n");

	/*initiator thread*/
	k_tid_t initiator_tid= k_thread_create(&thread_initiator_data, thread_initiator_stack_area,
						K_THREAD_STACK_SIZEOF(thread_initiator_stack_area),
						thread_initiator, (void *)&vec_num, NULL, NULL,
						PRIORITY, 0, K_NO_WAIT);

	/*responder thread*/
	k_tid_t responder_tid = k_thread_create(&thread_responder_data, thread_responder_stack_area,
						K_THREAD_STACK_SIZEOF(thread_responder_stack_area),
						thread_responder, (void *)&vec_num, NULL, NULL,
						PRIORITY, 0, K_NO_WAIT);

	k_thread_start(&thread_initiator_data);
	k_thread_start(&thread_responder_data);

	if ( 0 != k_thread_join(&thread_initiator_data, K_MSEC(5000)) )
	{
		PRINT_MSG("initiator thread stalled! Aborting.");
		k_thread_abort(initiator_tid);
	}
	if ( 0!= k_thread_join(&thread_responder_data, K_MSEC(5000)) )
	{
		PRINT_MSG("responder thread stalled! Aborting.");
		k_thread_abort(responder_tid);
	}

	PRINT_MSG("threads completed\n");

	/* check if Initiator and Responder computed the same values */

	zassert_mem_equal__(I_PRK_out, R_PRK_out, sizeof(R_PRK_out),
				"wrong prk_out");

	zassert_mem_equal__(I_prk_exporter, R_prk_exporter,
				sizeof(R_prk_exporter), "wrong prk_exporter");

	zassert_mem_equal__(I_master_secret, R_master_secret,
				sizeof(R_master_secret), "wrong master_secret");

	zassert_mem_equal__(I_master_salt, R_master_salt, sizeof(R_master_salt),
				"wrong master_salt");
}
