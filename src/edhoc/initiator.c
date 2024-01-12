/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdbool.h>
#include "edhoc_internal.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "edhoc/buffer_sizes.h"
#include "edhoc/hkdf_info.h"
#include "edhoc/messages.h"
#include "edhoc/okm.h"
#include "edhoc/plaintext.h"
#include "edhoc/prk.h"
#include "edhoc/retrieve_cred.h"
#include "edhoc/signature_or_mac_msg.h"
#include "edhoc/suites.h"
#include "edhoc/th.h"
#include "edhoc/txrx_wrapper.h"
#include "edhoc/ciphertext.h"
#include "edhoc/runtime_context.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"

#include "cbor/edhoc_encode_message_1.h"
#include "cbor/edhoc_decode_message_2.h"
#include "cbor/edhoc_encode_message_3.h"

/** 
 * @brief   			Parses message 2.
 * @param c 			Initiator context.
 * @param[in] msg2 		Message 2. 
 * @param[out] g_y		G_Y ephemeral public key of the responder.
 * @param[out] c_r		C_R connection identifier of the responder.
 * @param[out] ciphertext2	Ciphertext 2.
 * @retval			Ok or error code.
 */
static inline enum err msg2_parse(struct byte_array *msg2,
				  struct byte_array *g_y,
				  struct byte_array *c_r,
				  struct byte_array *ciphertext2)
{
	size_t decode_len = 0;
	struct m2 m;

	TRY_EXPECT(cbor_decode_m2(msg2->ptr, msg2->len, &m, &decode_len), 0);
	TRY(_memcpy_s(g_y->ptr, g_y->len, m.m2_G_Y_CIPHERTEXT_2.value,
		      g_y->len));
	PRINT_ARRAY("g_y", g_y->ptr, g_y->len);

	TRY(_memcpy_s(ciphertext2->ptr, ciphertext2->len,
		      m.m2_G_Y_CIPHERTEXT_2.value + g_y->len,
		      (uint32_t)(m.m2_G_Y_CIPHERTEXT_2.len - g_y->len)));

	ciphertext2->len = (uint32_t)m.m2_G_Y_CIPHERTEXT_2.len - g_y->len;
	PRINT_ARRAY("ciphertext2", ciphertext2->ptr, ciphertext2->len);

	if (m.m2_C_R_choice == m2_C_R_int_c) {
		TRY(encode_int(&m.m2_C_R_int, 1, c_r));
	} else {
		TRY(_memcpy_s(c_r->ptr, c_r->len, m.m2_C_R_bstr.value,
			      (uint32_t)m.m2_C_R_bstr.len));
		c_r->len = (uint32_t)m.m2_C_R_bstr.len;
	}
	PRINT_ARRAY("C_R_raw", c_r->ptr, c_r->len);

	return ok;
}

enum err msg1_gen(const struct edhoc_initiator_context *c,
		  struct runtime_context *rc)
{
	struct message_1 m1;

	/*METHOD_CORR*/
	m1.message_1_METHOD = (int32_t)c->method;

	/*SUITES_I*/
	if (c->suites_i.len == 1) {
		/* only one suite, encode into int */
		m1.message_1_SUITES_I_choice = message_1_SUITES_I_int_c;
		m1.message_1_SUITES_I_int = c->suites_i.ptr[0];
	} else if (c->suites_i.len > 1) {
		/* more than one suites, encode into array */
		m1.message_1_SUITES_I_choice = SUITES_I_suite_l_c;
		m1.SUITES_I_suite_l_suite_count = c->suites_i.len;
		for (uint32_t i = 0; i < c->suites_i.len; i++) {
			m1.SUITES_I_suite_l_suite[i] = c->suites_i.ptr[i];
		}
	}

	/* G_X ephemeral public key */
	m1.message_1_G_X.value = c->g_x.ptr;
	m1.message_1_G_X.len = c->g_x.len;

	/* C_I connection ID  of the initiator*/
	PRINT_ARRAY("C_I", c->c_i.ptr, c->c_i.len);
	if (c->c_i.len == 1 &&
	    ((0x00 <= c->c_i.ptr[0] && c->c_i.ptr[0] < 0x18) ||
	     (0x1F < c->c_i.ptr[0] && c->c_i.ptr[0] <= 0x37))) {
		m1.message_1_C_I_choice = message_1_C_I_int_c;
		TRY(decode_int(&c->c_i, &m1.message_1_C_I_int));
	} else {
		m1.message_1_C_I_choice = message_1_C_I_bstr_c;
		m1.message_1_C_I_bstr.value = c->c_i.ptr;
		m1.message_1_C_I_bstr.len = c->c_i.len;
	}

	if (c->ead_1.len != 0) {
		/* ead_1 unprotected opaque auxiliary data */
		m1.message_1_ead_1.value = c->ead_1.ptr;
		m1.message_1_ead_1.len = c->ead_1.len;
		m1.message_1_ead_1_present = true;
	} else {
		m1.message_1_ead_1_present = false;
	}

	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_message_1(rc->msg.ptr, rc->msg.len, &m1,
					 &payload_len_out),
		   0);
	rc->msg.len = (uint32_t)payload_len_out;

	PRINT_ARRAY("message_1 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);

	TRY(get_suite((enum suite_label)c->suites_i.ptr[c->suites_i.len - 1],
		      &rc->suite));
	/* Calculate hash of msg1 for TH2. */
	TRY(hash(rc->suite.edhoc_hash, &rc->msg, &rc->msg1_hash));
	return ok;
}

static enum err msg2_process(const struct edhoc_initiator_context *c,
			     struct runtime_context *rc,
			     struct cred_array *cred_r_array,
			     struct byte_array *c_r, bool static_dh_i,
			     bool static_dh_r, struct byte_array *th3,
			     struct byte_array *PRK_3e2m)
{
	BYTE_ARRAY_NEW(g_y, G_Y_SIZE, get_ecdh_pk_len(rc->suite.edhoc_ecdh));
	uint32_t ciphertext_len = rc->msg.len - g_y.len - c_r->len;
	ciphertext_len -= BSTR_ENCODING_OVERHEAD(ciphertext_len);
	BYTE_ARRAY_NEW(ciphertext, CIPHERTEXT2_SIZE, ciphertext_len);
	BYTE_ARRAY_NEW(plaintext, PLAINTEXT2_SIZE, ciphertext.len);
	PRINT_ARRAY("message_2 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);

	/*parse the message*/
	TRY(msg2_parse(&rc->msg, &g_y, c_r, &ciphertext));

	/*calculate the DH shared secret*/
	BYTE_ARRAY_NEW(g_xy, ECDH_SECRET_SIZE, ECDH_SECRET_SIZE);

	TRY(shared_secret_derive(rc->suite.edhoc_ecdh, &c->x, &g_y, g_xy.ptr));
	PRINT_ARRAY("G_XY (ECDH shared secret) ", g_xy.ptr, g_xy.len);

	/*calculate th2*/
	BYTE_ARRAY_NEW(th2, HASH_SIZE, get_hash_len(rc->suite.edhoc_hash));

	TRY(th2_calculate(rc->suite.edhoc_hash, &rc->msg1_hash, &g_y, c_r,
			  &th2));
	PRINT_ARRAY("TH_2", th2.ptr, th2.len);

	/*calculate PRK_2e*/
	BYTE_ARRAY_NEW(PRK_2e, PRK_SIZE, PRK_SIZE);
	TRY(hkdf_extract(rc->suite.edhoc_hash, &th2, &g_xy, PRK_2e.ptr));
	PRINT_ARRAY("PRK_2e", PRK_2e.ptr, PRK_2e.len);

	BYTE_ARRAY_NEW(sign_or_mac, SIG_OR_MAC_SIZE, SIG_OR_MAC_SIZE);
	BYTE_ARRAY_NEW(id_cred_r, ID_CRED_R_SIZE, ID_CRED_R_SIZE);

	plaintext.len = ciphertext.len;
	TRY(check_buffer_size(PLAINTEXT2_SIZE, plaintext.len));

	TRY(ciphertext_decrypt_split(CIPHERTEXT2, &rc->suite, &id_cred_r,
				     &sign_or_mac, &rc->ead, &PRK_2e, &th2,
				     &ciphertext, &plaintext));

	/*check the authenticity of the responder*/
	BYTE_ARRAY_NEW(cred_r, CRED_R_SIZE, CRED_R_SIZE);
	BYTE_ARRAY_NEW(pk, PK_SIZE, PK_SIZE);
	BYTE_ARRAY_NEW(g_r, G_R_SIZE, G_R_SIZE);
	TRY(retrieve_cred(static_dh_r, cred_r_array, &id_cred_r, &cred_r, &pk,
			  &g_r));
	PRINT_ARRAY("CRED_R", cred_r.ptr, cred_r.len);
	PRINT_ARRAY("pk", pk.ptr, pk.len);
	PRINT_ARRAY("g_r", g_r.ptr, g_r.len);

	/*derive prk_3e2m*/
	TRY(prk_derive(static_dh_r, rc->suite, SALT_3e2m, &th2, &PRK_2e, &g_r,
		       &c->x, PRK_3e2m->ptr));
	PRINT_ARRAY("prk_3e2m", PRK_3e2m->ptr, PRK_3e2m->len);

	TRY(signature_or_mac(VERIFY, static_dh_r, &rc->suite, NULL, &pk,
			     PRK_3e2m, &th2, &id_cred_r, &cred_r, &rc->ead,
			     MAC_2, &sign_or_mac));

	TRY(th34_calculate(rc->suite.edhoc_hash, &th2, &plaintext, &cred_r,
			   th3));

	/*derive prk_4e3m*/
	TRY(prk_derive(static_dh_i, rc->suite, SALT_4e3m, th3, PRK_3e2m, &g_y,
		       &c->i, rc->prk_4e3m.ptr));
	PRINT_ARRAY("prk_4e3m", rc->prk_4e3m.ptr, rc->prk_4e3m.len);

	return ok;
}

static enum err msg3_only_gen(const struct edhoc_initiator_context *c,
			      struct runtime_context *rc, bool static_dh_i,
			      struct byte_array *th3,
			      struct byte_array *PRK_3e2m,
			      struct byte_array *prk_out)
{
	BYTE_ARRAY_NEW(plaintext, PLAINTEXT3_SIZE,
		       c->id_cred_i.len + (SIG_OR_MAC_SIZE + 2) + c->ead_3.len);
	BYTE_ARRAY_NEW(ciphertext, CIPHERTEXT3_SIZE,
		       plaintext.len + ENCODING_OVERHEAD);
	/*calculate Signature_or_MAC_3*/
	BYTE_ARRAY_NEW(sign_or_mac_3, SIG_OR_MAC_SIZE, SIG_OR_MAC_SIZE);
	TRY(signature_or_mac(GENERATE, static_dh_i, &rc->suite, &c->sk_i,
			     &c->pk_i, &rc->prk_4e3m, th3, &c->id_cred_i,
			     &c->cred_i, &c->ead_3, MAC_3, &sign_or_mac_3));

	/*create plaintext3 and ciphertext3*/
	TRY(ciphertext_gen(CIPHERTEXT3, &rc->suite, &c->id_cred_i,
			   &sign_or_mac_3, &c->ead_3, PRK_3e2m, th3,
			   &ciphertext, &plaintext));

	/*massage 3 create and send*/
	TRY(encode_bstr(&ciphertext, &rc->msg));
	PRINT_ARRAY("msg3", rc->msg.ptr, rc->msg.len);

	/*TH4*/
	TRY(th34_calculate(rc->suite.edhoc_hash, th3, &plaintext, &c->cred_i,
			   &rc->th4));

	/*PRK_out*/
	TRY(edhoc_kdf(rc->suite.edhoc_hash, &rc->prk_4e3m, PRK_out, &rc->th4,
		      prk_out));
	return ok;
}

enum err msg3_gen(const struct edhoc_initiator_context *c,
		  struct runtime_context *rc, struct cred_array *cred_r_array,
		  struct byte_array *c_r, struct byte_array *prk_out)
{
	bool static_dh_i = false, static_dh_r = false;
	authentication_type_get(c->method, &static_dh_i, &static_dh_r);
	BYTE_ARRAY_NEW(th3, HASH_SIZE, HASH_SIZE);
	BYTE_ARRAY_NEW(PRK_3e2m, PRK_SIZE, PRK_SIZE);

	/*process message 2*/
	TRY(msg2_process(c, rc, cred_r_array, c_r, static_dh_i, static_dh_r,
			 &th3, &PRK_3e2m));

	/*generate message 3*/
	msg3_only_gen(c, rc, static_dh_i, &th3, &PRK_3e2m, prk_out);
	return ok;
}

#ifdef MESSAGE_4
enum err msg4_process(struct runtime_context *rc)
{
	PRINT_ARRAY("message4 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);

	BYTE_ARRAY_NEW(ciphertext4, CIPHERTEXT4_SIZE, CIPHERTEXT4_SIZE);
	TRY(decode_bstr(&rc->msg, &ciphertext4));
	PRINT_ARRAY("ciphertext_4", ciphertext4.ptr, ciphertext4.len);

	BYTE_ARRAY_NEW(plaintext4,
		       PLAINTEXT4_SIZE + get_aead_mac_len(rc->suite.edhoc_aead),
		       ciphertext4.len);
	TRY(ciphertext_decrypt_split(CIPHERTEXT4, &rc->suite, &NULL_ARRAY,
				     &NULL_ARRAY, &rc->ead, &rc->prk_4e3m,
				     &rc->th4, &ciphertext4, &plaintext4));
	return ok;
}
#endif // MESSAGE_4

enum err edhoc_initiator_run_extended(
	const struct edhoc_initiator_context *c,
	struct cred_array *cred_r_array, struct byte_array *err_msg,
	struct byte_array *c_r_bytes, struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead24))
{
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);

	/*create and send message 1*/
	TRY(msg1_gen(c, &rc));
	TRY(tx(c->sock, &rc.msg));

	/*receive message 2*/
	PRINT_MSG("waiting to receive message 2...\n");
	rc.msg.len = sizeof(rc.msg_buf);
	TRY(rx(c->sock, &rc.msg));

	/*create and send message 3*/
	TRY(msg3_gen(c, &rc, cred_r_array, c_r_bytes, prk_out));
	TRY(ead_process(c->params_ead_process, &rc.ead));
	TRY(tx(c->sock, &rc.msg));

	/*receive message 4*/
#ifdef MESSAGE_4
	PRINT_MSG("waiting to receive message 4...\n");
	rc.msg.len = sizeof(rc.msg_buf);
	TRY(rx(c->sock, &rc.msg));
	TRY(msg4_process(&rc));
	TRY(ead_process(c->params_ead_process, &rc.ead));
#endif // MESSAGE_4
	return ok;
}

enum err edhoc_initiator_run(
	const struct edhoc_initiator_context *c,
	struct cred_array *cred_r_array, struct byte_array *err_msg,
	struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead24))
{
	BYTE_ARRAY_NEW(c_r, C_R_SIZE, C_R_SIZE);

	return edhoc_initiator_run_extended(c, cred_r_array, err_msg, &c_r,
					    prk_out, tx, rx, ead_process);
}
