/*
 * Copyright (c) 2022 Eriptic Technologies.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include <zephyr/debug/thread_analyzer.h>

#include <edhoc.h>

#include "edhoc_test_vectors_p256_v15.h"
#include "latency.h"

uint8_t I_prk_exporter_buf[32];
struct byte_array I_prk_exporter = { .ptr = I_prk_exporter_buf,
				     .len = sizeof(I_prk_exporter_buf) };

uint8_t I_master_secret_buf[16];
struct byte_array I_master_secret = { .ptr = I_master_secret_buf,
				      .len = sizeof(I_master_secret_buf) };

uint8_t I_master_salt_buf[8];
struct byte_array I_master_salt = { .ptr = I_master_salt_buf,
				    .len = sizeof(I_master_salt_buf) };

uint8_t I_PRK_out_buf[32];
struct byte_array I_PRK_out = { .ptr = I_PRK_out_buf,
				.len = sizeof(I_PRK_out_buf) };

uint8_t I_err_msg_buf[0];
struct byte_array I_err_msg = { .ptr = I_err_msg_buf,
				.len = sizeof(I_err_msg_buf) };
/******************************************************************************/

uint8_t R_prk_exporter_buf[32];
struct byte_array R_prk_exporter = { .ptr = R_prk_exporter_buf,
				     .len = sizeof(R_prk_exporter_buf) };

uint8_t R_master_secret_buf[16];
struct byte_array R_master_secret = { .ptr = R_master_secret_buf,
				      .len = sizeof(R_master_secret_buf) };

uint8_t R_master_salt_buf[8];
struct byte_array R_master_salt = { .ptr = R_master_salt_buf,
				    .len = sizeof(R_master_salt_buf) };

uint8_t R_PRK_out_buf[32];
struct byte_array R_PRK_out = { .ptr = R_PRK_out_buf,
				.len = sizeof(R_PRK_out_buf) };

uint8_t R_err_msg_buf[0];
struct byte_array R_err_msg = { .ptr = R_err_msg_buf,
				.len = sizeof(R_err_msg_buf) };

/* size of stack area used by each thread */
#define STACKSIZE 7500
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
	if (k_sem_take(sem, K_FOREVER) != 0) {
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

enum err tx_initiator(void *sock, struct byte_array *data)
{
	enum err r = copy_message(data->ptr, data->len);
	if (r != ok) {
		return r;
	}
	semaphore_give(&tx_initiator_completed);
	return ok;
}

enum err tx_responder(void *sock, struct byte_array *data)
{
	//PRINTF("tx_responder data len: %d\n", data->len);
	enum err r = copy_message(data->ptr, data->len);
	if (r != ok) {
		return r;
	}
	//PRINTF("msg_exchange_buf_len: %d\n",msg_exchange_buf_len);
	semaphore_give(&tx_responder_completed);
	return ok;
}

enum err rx_initiator(void *sock, struct byte_array *data)
{
	PRINTF("msg_exchange_buf_len: %d\n", msg_exchange_buf_len);
	return semaphore_take(&tx_responder_completed, data->ptr, &data->len);
}
enum err rx_responder(void *sock, struct byte_array *data)
{
	return semaphore_take(&tx_initiator_completed, data->ptr, &data->len);
}
enum err ead_process(void *params, struct byte_array *ead13)
{
	return ok;
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
	int vec_num_i = *((int *)vec_num) - 1;

	enum err r;

	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

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

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

	r = edhoc_initiator_run(&c_i, &cred_r_array, &I_err_msg, &I_PRK_out,
				tx_initiator, rx_initiator, ead_process);
	if (r != ok) {
		goto end;
	}

	PRINT_ARRAY("I_PRK_out", I_PRK_out.ptr, I_PRK_out.len);

	r = prk_out2exporter(SHA_256, &I_PRK_out, &I_prk_exporter);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("I_prk_exporter", I_prk_exporter.ptr, I_prk_exporter.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &I_prk_exporter,
			   &I_master_secret);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Secret", I_master_secret.ptr,
		    I_master_secret.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &I_prk_exporter,
			   &I_master_salt);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Salt", I_master_salt.ptr, I_master_salt.len);

#ifdef REPORT_STACK_USAGE
	thread_analyzer_print();
#endif

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
	int vec_num_i = *((int *)vec_num) - 1;

	/* test vector inputs */
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

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

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };
	r = edhoc_responder_run(&c_r, &cred_i_array, &R_err_msg, &R_PRK_out,
				tx_responder, rx_responder, ead_process);
	if (r != ok) {
		goto end;
	}

	PRINT_ARRAY("R_PRK_out", R_PRK_out.ptr, R_PRK_out.len);

	r = prk_out2exporter(SHA_256, &R_PRK_out, &R_prk_exporter);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("R_prk_exporter", R_prk_exporter.ptr, R_prk_exporter.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &R_prk_exporter,
			   &R_master_secret);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Secret", R_master_secret.ptr,
		    R_master_secret.len);

	r = edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &R_prk_exporter,
			   &R_master_salt);
	if (r != ok) {
		goto end;
	}
	PRINT_ARRAY("OSCORE Master Salt", R_master_salt.ptr, R_master_salt.len);

#ifdef REPORT_STACK_USAGE
	thread_analyzer_print();
#endif

	return;
end:
	PRINTF("An error has occurred. Error code: %d\n", r);
}

int test_initiator_responder_interaction(int vec_num)
{
	PRINT_MSG("start initiator_responder_interaction\n");

	/*initiator thread*/
	k_tid_t initiator_tid = k_thread_create(
		&thread_initiator_data, thread_initiator_stack_area,
		K_THREAD_STACK_SIZEOF(thread_initiator_stack_area),
		thread_initiator, (void *)&vec_num, NULL, NULL, PRIORITY, 0,
		K_NO_WAIT);

	/*responder thread*/
	k_tid_t responder_tid = k_thread_create(
		&thread_responder_data, thread_responder_stack_area,
		K_THREAD_STACK_SIZEOF(thread_responder_stack_area),
		thread_responder, (void *)&vec_num, NULL, NULL, PRIORITY, 0,
		K_NO_WAIT);

	k_thread_start(&thread_initiator_data);
	k_thread_start(&thread_responder_data);

	if (0 != k_thread_join(&thread_initiator_data, K_FOREVER)) {
		PRINT_MSG("initiator thread stalled! Aborting.");
		k_thread_abort(initiator_tid);
	}
	if (0 != k_thread_join(&thread_responder_data, K_FOREVER)) {
		PRINT_MSG("responder thread stalled! Aborting.");
		k_thread_abort(responder_tid);
	}

	PRINT_MSG("threads completed\n");

	/* check if Initiator and Responder computed the same values */

	zassert_mem_equal__(I_PRK_out.ptr, R_PRK_out.ptr, R_PRK_out.len,
			    "wrong prk_out");

	zassert_mem_equal__(I_prk_exporter.ptr, R_prk_exporter.ptr,
			    R_prk_exporter.len, "wrong prk_exporter");

	zassert_mem_equal__(I_master_secret.ptr, R_master_secret.ptr,
			    R_master_secret.len, "wrong master_secret");

	zassert_mem_equal__(I_master_salt.ptr, R_master_salt.ptr,
			    R_master_salt.len, "wrong master_salt");
	return 0;
}

void t_initiator_responder_interaction1()
{
	MEASURE_LATENCY(test_initiator_responder_interaction(1));
}

void t_initiator_responder_interaction2()
{
	MEASURE_LATENCY(test_initiator_responder_interaction(2));
}

/* A peer that gave up must not block the other one forever */
#define HANDSHAKE_RX_TIMEOUT K_SECONDS(5)

static enum err handshake_rx(struct k_sem *sem, struct byte_array *data)
{
	if (k_sem_take(sem, HANDSHAKE_RX_TIMEOUT) != 0 ||
	    msg_exchange_buf_len > data->len) {
		return buffer_to_small;
	}
	memcpy(data->ptr, msg_exchange_buf, msg_exchange_buf_len);
	data->len = msg_exchange_buf_len;
	return ok;
}

static enum err handshake_rx_initiator(void *sock, struct byte_array *data)
{
	return handshake_rx(&tx_responder_completed, data);
}

static enum err handshake_rx_responder(void *sock, struct byte_array *data)
{
	return handshake_rx(&tx_initiator_completed, data);
}

/* The credentials of a handshake. The rest comes from test vector 1, which
 * uses method 0 and suite 2. */
struct handshake {
	struct byte_array id_cred_i;
	struct byte_array cred_i;
	struct byte_array id_cred_r;
	struct byte_array cred_r;
	struct cred_array *cred_i_array;
	struct cred_array *cred_r_array;
	uint8_t i_prk_out[32];
	uint8_t r_prk_out[32];
	enum err i_result;
	enum err r_result;
};

static void handshake_initiator(void *arg, void *dummy2, void *dummy3)
{
	struct handshake *h = arg;
	const struct test_vector *v = &test_vectors[0];
	struct byte_array prk_out = { .ptr = h->i_prk_out, .len = 32 };
	struct edhoc_initiator_context c = {
		.c_i = { .ptr = (uint8_t *)v->c_i, .len = v->c_i_len },
		.method = (enum method_type) * v->method,
		.suites_i = { .ptr = (uint8_t *)v->SUITES_I,
			      .len = v->SUITES_I_len },
		.id_cred_i = h->id_cred_i,
		.cred_i = h->cred_i,
		.g_x = { .ptr = (uint8_t *)v->g_x_raw, .len = v->g_x_raw_len },
		.x = { .ptr = (uint8_t *)v->x_raw, .len = v->x_raw_len },
		.sk_i = { .ptr = (uint8_t *)v->sk_i_raw,
			  .len = v->sk_i_raw_len },
		.pk_i = { .ptr = (uint8_t *)v->pk_i_raw,
			  .len = v->pk_i_raw_len },
	};

	h->i_result = edhoc_initiator_run(&c, h->cred_r_array, &I_err_msg,
					  &prk_out, tx_initiator,
					  handshake_rx_initiator, ead_process);
}

static void handshake_responder(void *arg, void *dummy2, void *dummy3)
{
	struct handshake *h = arg;
	const struct test_vector *v = &test_vectors[0];
	struct byte_array prk_out = { .ptr = h->r_prk_out, .len = 32 };
	struct edhoc_responder_context c = {
		.c_r = { .ptr = (uint8_t *)v->c_r, .len = v->c_r_len },
		.suites_r = { .ptr = (uint8_t *)v->SUITES_R,
			      .len = v->SUITES_R_len },
		.id_cred_r = h->id_cred_r,
		.cred_r = h->cred_r,
		.g_y = { .ptr = (uint8_t *)v->g_y_raw, .len = v->g_y_raw_len },
		.y = { .ptr = (uint8_t *)v->y_raw, .len = v->y_raw_len },
		.sk_r = { .ptr = (uint8_t *)v->sk_r_raw,
			  .len = v->sk_r_raw_len },
		.pk_r = { .ptr = (uint8_t *)v->pk_r_raw,
			  .len = v->pk_r_raw_len },
	};

	h->r_result = edhoc_responder_run(&c, h->cred_i_array, &R_err_msg,
					  &prk_out, tx_responder,
					  handshake_rx_responder, ead_process);
}

static void handshake_run(struct handshake *h)
{
	h->i_result = unexpected_result_from_ext_lib;
	h->r_result = unexpected_result_from_ext_lib;
	k_sem_reset(&tx_initiator_completed);
	k_sem_reset(&tx_responder_completed);

	k_thread_create(&thread_responder_data, thread_responder_stack_area,
			K_THREAD_STACK_SIZEOF(thread_responder_stack_area),
			handshake_responder, h, NULL, NULL, PRIORITY, 0,
			K_NO_WAIT);
	k_thread_create(&thread_initiator_data, thread_initiator_stack_area,
			K_THREAD_STACK_SIZEOF(thread_initiator_stack_area),
			handshake_initiator, h, NULL, NULL, PRIORITY, 0,
			K_NO_WAIT);

	k_thread_join(&thread_initiator_data, K_FOREVER);
	k_thread_join(&thread_responder_data, K_FOREVER);
}

void t_message_3_larger_than_message_2(void)
{
	const struct test_vector *v = &test_vectors[0];
	static const uint8_t id_cred_r[] = { 0xa1, 0x04, 0x41, 0x32 };
	/* ID_CRED_R is a compact kid, ID_CRED_I carries a certificate */
	struct other_party_cred cred_r = {
		.id_cred = { .ptr = (uint8_t *)id_cred_r,
			     .len = sizeof(id_cred_r) },
		.cred = { .ptr = (uint8_t *)v->cred_r, .len = v->cred_r_len },
		.pk = { .ptr = (uint8_t *)v->pk_r_raw, .len = v->pk_r_raw_len },
	};
	struct other_party_cred cred_i = {
		.id_cred = { .ptr = (uint8_t *)v->id_cred_i,
			     .len = v->id_cred_i_len },
		.cred = { .ptr = (uint8_t *)v->cred_i, .len = v->cred_i_len },
		.pk = { .ptr = (uint8_t *)v->pk_i_raw, .len = v->pk_i_raw_len },
		.ca = { .ptr = (uint8_t *)v->ca_i, .len = v->ca_i_len },
		.ca_pk = { .ptr = (uint8_t *)v->ca_i_pk,
			   .len = v->ca_i_pk_len },
	};
	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };
	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };
	struct handshake h = {
		.id_cred_i = cred_i.id_cred,
		.cred_i = cred_i.cred,
		.id_cred_r = cred_r.id_cred,
		.cred_r = cred_r.cred,
		.cred_i_array = &cred_i_array,
		.cred_r_array = &cred_r_array,
	};

	handshake_run(&h);

	zassert_equal(h.i_result, ok, "initiator failed");
	zassert_equal(h.r_result, ok, "responder failed");
	zassert_mem_equal__(h.i_prk_out, h.r_prk_out, 32, "wrong PRK_out");
}
