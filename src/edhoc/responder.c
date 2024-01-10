/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/buffer_sizes.h"
#include "edhoc_internal.h"

#include "common/memcpy_s.h"
#include "common/print_util.h"
#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"

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
#include "edhoc/suites.h"
#include "edhoc/runtime_context.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/int_encode_decode.h"

#include "cbor/edhoc_decode_message_1.h"
#include "cbor/edhoc_encode_message_2.h"
#include "cbor/edhoc_decode_message_3.h"

#define CBOR_UINT_SINGLE_BYTE_UINT_MAX_VALUE (0x17)
#define CBOR_UINT_MULTI_BYTE_UINT_MAX_VALUE (0x17)
#define CBOR_BSTR_TYPE_MIN_VALUE (0x40)
#define CBOR_BSTR_TYPE_MAX_VALUE (0x57)

/**
 * @brief   			Parses message 1.
 * @param[in] msg1 		Message 1.
 * @param[out] method 		EDHOC method.
 * @param[out] suites_i 	Cipher suites suported by the initiator
 * @param[out] g_x 		Public ephemeral key of the initiator.
 * @param[out] c_i 		Connection identifier of the initiator.
 * @param[out] ead1 		External authorized data 1.
 * @retval 			Ok or error code.
 */
static inline enum err
msg1_parse(struct byte_array *msg1, enum method_type *method,
	   struct byte_array *suites_i, struct byte_array *g_x,
	   struct byte_array *c_i, struct byte_array *ead1)
{
	uint32_t i;
	struct message_1 m;
	size_t decode_len = 0;

	TRY_EXPECT(cbor_decode_message_1(msg1->ptr, msg1->len, &m, &decode_len),
		   0);

	/*METHOD*/
	if ((m.message_1_METHOD > INITIATOR_SDHK_RESPONDER_SDHK) ||
	    (m.message_1_METHOD < INITIATOR_SK_RESPONDER_SK)) {
		return wrong_parameter;
	}
	*method = (enum method_type)m.message_1_METHOD;
	PRINTF("msg1 METHOD: %d\n", (int)*method);

	/*SUITES_I*/
	if (m.message_1_SUITES_I_choice == message_1_SUITES_I_int_c) {
		/*the initiator supports only one suite*/
		suites_i->ptr[0] = (uint8_t)m.message_1_SUITES_I_int;
		suites_i->len = 1;
	} else {
		if (0 == m.SUITES_I_suite_l_suite_count) {
			return suites_i_list_empty;
		}

		/*the initiator supports more than one suite*/
		if (m.SUITES_I_suite_l_suite_count > suites_i->len) {
			return suites_i_list_to_long;
		}

		for (i = 0; i < m.SUITES_I_suite_l_suite_count; i++) {
			suites_i->ptr[i] = (uint8_t)m.SUITES_I_suite_l_suite[i];
		}
		suites_i->len = (uint32_t)m.SUITES_I_suite_l_suite_count;
	}
	PRINT_ARRAY("msg1 SUITES_I", suites_i->ptr, suites_i->len);

	/*G_X*/
	TRY(_memcpy_s(g_x->ptr, g_x->len, m.message_1_G_X.value,
		      (uint32_t)m.message_1_G_X.len));
	g_x->len = (uint32_t)m.message_1_G_X.len;
	PRINT_ARRAY("msg1 G_X", g_x->ptr, g_x->len);

	/*C_I*/
	if (m.message_1_C_I_choice == message_1_C_I_int_c) {
		c_i->ptr[0] = (uint8_t)m.message_1_C_I_int;
		c_i->len = 1;
	} else {
		TRY(_memcpy_s(c_i->ptr, c_i->len, m.message_1_C_I_bstr.value,
			      (uint32_t)m.message_1_C_I_bstr.len));
		c_i->len = (uint32_t)m.message_1_C_I_bstr.len;
	}
	PRINT_ARRAY("msg1 C_I_raw", c_i->ptr, c_i->len);

	/*ead_1*/
	if (m.message_1_ead_1_present) {
		TRY(_memcpy_s(ead1->ptr, ead1->len, m.message_1_ead_1.value,
			      (uint32_t)m.message_1_ead_1.len));
		ead1->len = (uint32_t)m.message_1_ead_1.len;
		PRINT_ARRAY("msg1 ead_1", ead1->ptr, ead1->len);
	}
	return ok;
}

/**
 * @brief   			Checks if the selected cipher suite 
 * 				(the first in the list received from the 
 * 				initiator) is supported.
 * @param selected 		The selected suite.
 * @param[in] suites_r 		The list of suported cipher suites.
 * @retval  			True if supported.
 */
static inline bool selected_suite_is_supported(uint8_t selected,
					       struct byte_array *suites_r)
{
	for (uint32_t i = 0; i < suites_r->len; i++) {
		if (suites_r->ptr[i] == selected)
			PRINTF("Suite %d will be used in this EDHOC run.\n",
			       selected);
		return true;
	}
	return false;
}

/**
 * @brief   			Encodes message 2.
 * @param[in] g_y 		Public ephemeral DH key of the responder. 
 * @param[in] c_r 		Connection identifier of the responder.
 * @param[in] ciphertext_2 	The ciphertext.
 * @param[out] msg2 		The encoded message.
 * @retval  			Ok or error code.
 */
static inline enum err msg2_encode(const struct byte_array *g_y,
				   struct byte_array *c_r,
				   const struct byte_array *ciphertext_2,
				   struct byte_array *msg2)
{
	size_t payload_len_out;
	struct m2 m;

	BYTE_ARRAY_NEW(g_y_ciphertext_2, G_Y_SIZE + CIPHERTEXT2_SIZE,
		       g_y->len + ciphertext_2->len);

	memcpy(g_y_ciphertext_2.ptr, g_y->ptr, g_y->len);
	memcpy(g_y_ciphertext_2.ptr + g_y->len, ciphertext_2->ptr,
	       ciphertext_2->len);

	/*Encode g_y_ciphertext_2*/
	m.m2_G_Y_CIPHERTEXT_2.value = g_y_ciphertext_2.ptr;
	m.m2_G_Y_CIPHERTEXT_2.len = g_y_ciphertext_2.len;

	/*Encode C_R*/
	PRINT_ARRAY("C_R", c_r->ptr, c_r->len);
	if (c_r->len == 1 && (c_r->ptr[0] < 0x18 ||
			      (0x1F < c_r->ptr[0] && c_r->ptr[0] <= 0x37))) {
		m.m2_C_R_choice = m2_C_R_int_c;
		TRY(decode_int(c_r, &m.m2_C_R_int));
	} else {
		m.m2_C_R_choice = m2_C_R_bstr_c;
		m.m2_C_R_bstr.value = c_r->ptr;
		m.m2_C_R_bstr.len = c_r->len;
	}

	TRY_EXPECT(cbor_encode_m2(msg2->ptr, msg2->len, &m, &payload_len_out),
		   0);
	msg2->len = (uint32_t)payload_len_out;

	PRINT_ARRAY("message_2 (CBOR Sequence)", msg2->ptr, msg2->len);
	return ok;
}

enum err msg2_gen(struct edhoc_responder_context *c, struct runtime_context *rc,
		  struct byte_array *c_i)
{
	PRINT_ARRAY("message_1 (CBOR Sequence)", rc->msg.ptr, rc->msg.len);

	enum method_type method = INITIATOR_SK_RESPONDER_SK;
	BYTE_ARRAY_NEW(suites_i, SUITES_I_SIZE, SUITES_I_SIZE);
	BYTE_ARRAY_NEW(g_x, G_X_SIZE, G_X_SIZE);

	TRY(msg1_parse(&rc->msg, &method, &suites_i, &g_x, c_i, &rc->ead));

	// TODO this may be a vulnerability in case suites_i.len is zero
	if (!(selected_suite_is_supported(suites_i.ptr[suites_i.len - 1],
					  &c->suites_r))) {
		// TODO implement here the sending of an error message
		return error_message_sent;
	}

	/*get cipher suite*/
	TRY(get_suite((enum suite_label)suites_i.ptr[suites_i.len - 1],
		      &rc->suite));

	bool static_dh_r;
	authentication_type_get(method, &rc->static_dh_i, &static_dh_r);

	/******************* create and send message 2*************************/
	BYTE_ARRAY_NEW(th2, HASH_SIZE, get_hash_len(rc->suite.edhoc_hash));
	TRY(hash(rc->suite.edhoc_hash, &rc->msg, &rc->msg1_hash));
	TRY(th2_calculate(rc->suite.edhoc_hash, &rc->msg1_hash, &c->g_y,
			  &c->c_r, &th2));

	/*calculate the DH shared secret*/
	BYTE_ARRAY_NEW(g_xy, ECDH_SECRET_SIZE, ECDH_SECRET_SIZE);
	TRY(shared_secret_derive(rc->suite.edhoc_ecdh, &c->y, &g_x, g_xy.ptr));

	PRINT_ARRAY("G_XY (ECDH shared secret) ", g_xy.ptr, g_xy.len);

	BYTE_ARRAY_NEW(PRK_2e, PRK_SIZE, PRK_SIZE);
	TRY(hkdf_extract(rc->suite.edhoc_hash, &th2, &g_xy, PRK_2e.ptr));
	PRINT_ARRAY("PRK_2e", PRK_2e.ptr, PRK_2e.len);

	/*derive prk_3e2m*/
	TRY(prk_derive(static_dh_r, rc->suite, SALT_3e2m, &th2, &PRK_2e, &g_x,
		       &c->r, rc->prk_3e2m.ptr));
	PRINT_ARRAY("prk_3e2m", rc->prk_3e2m.ptr, rc->prk_3e2m.len);

	/*compute signature_or_MAC_2*/
	BYTE_ARRAY_NEW(sign_or_mac_2, SIGNATURE_SIZE,
		       get_signature_len(rc->suite.edhoc_sign));

	TRY(signature_or_mac(GENERATE, static_dh_r, &rc->suite, &c->sk_r,
			     &c->pk_r, &rc->prk_3e2m, &th2, &c->id_cred_r,
			     &c->cred_r, &c->ead_2, MAC_2, &sign_or_mac_2));

	/*compute ciphertext_2*/
	BYTE_ARRAY_NEW(plaintext_2, PLAINTEXT2_SIZE,
		       c->id_cred_r.len + sign_or_mac_2.len +
			       SIG_OR_MAC_SIZE_ENCODING_OVERHEAD +
			       c->ead_2.len);
	BYTE_ARRAY_NEW(ciphertext_2, CIPHERTEXT2_SIZE, plaintext_2.len);

	TRY(ciphertext_gen(CIPHERTEXT2, &rc->suite, &c->id_cred_r,
			   &sign_or_mac_2, &c->ead_2, &PRK_2e, &th2,
			   &ciphertext_2, &plaintext_2));

	/* Clear the message buffer. */
	memset(rc->msg.ptr, 0, rc->msg.len);
	rc->msg.len = sizeof(rc->msg_buf);
	/*message 2 create*/
	TRY(msg2_encode(&c->g_y, &c->c_r, &ciphertext_2, &rc->msg));

	TRY(th34_calculate(rc->suite.edhoc_hash, &th2, &plaintext_2, &c->cred_r,
			   &rc->th3));

	return ok;
}

enum err msg3_process(struct edhoc_responder_context *c,
		      struct runtime_context *rc,
		      struct cred_array *cred_i_array,
		      struct byte_array *prk_out,
		      struct byte_array *initiator_pk)
{
	BYTE_ARRAY_NEW(ctxt3, CIPHERTEXT3_SIZE, rc->msg.len);
	TRY(decode_bstr(&rc->msg, &ctxt3));
	PRINT_ARRAY("CIPHERTEXT_3", ctxt3.ptr, ctxt3.len);

	BYTE_ARRAY_NEW(id_cred_i, ID_CRED_I_SIZE, ID_CRED_I_SIZE);
	BYTE_ARRAY_NEW(sign_or_mac, SIG_OR_MAC_SIZE, SIG_OR_MAC_SIZE);

	PRINTF("PLAINTEXT3_SIZE: %d\n", PLAINTEXT3_SIZE);
	PRINTF("ctxt3.len: %d\n", ctxt3.len);
#if defined(_WIN32)
	BYTE_ARRAY_NEW(ptxt3,
		       PLAINTEXT3_SIZE + 16, // 16 is max aead mac length
		       ctxt3.len);
#else
	BYTE_ARRAY_NEW(ptxt3,
		       PLAINTEXT3_SIZE + get_aead_mac_len(rc->suite.edhoc_aead),
		       ctxt3.len);
#endif

	TRY(ciphertext_decrypt_split(CIPHERTEXT3, &rc->suite, &id_cred_i,
				     &sign_or_mac, &rc->ead, &rc->prk_3e2m,
				     &rc->th3, &ctxt3, &ptxt3));

	/*check the authenticity of the initiator*/
	BYTE_ARRAY_NEW(cred_i, CRED_I_SIZE, CRED_I_SIZE);
	BYTE_ARRAY_NEW(pk, PK_SIZE, PK_SIZE);
	BYTE_ARRAY_NEW(g_i, G_I_SIZE, G_I_SIZE);

	TRY(retrieve_cred(rc->static_dh_i, cred_i_array, &id_cred_i, &cred_i,
			  &pk, &g_i));
	PRINT_ARRAY("CRED_I", cred_i.ptr, cred_i.len);
	PRINT_ARRAY("pk", pk.ptr, pk.len);
	PRINT_ARRAY("g_i", g_i.ptr, g_i.len);

	/* Export public key. */
	if ((NULL != initiator_pk) && (NULL != initiator_pk->ptr)) {
		_memcpy_s(initiator_pk->ptr, initiator_pk->len, pk.ptr, pk.len);
		initiator_pk->len = pk.len;
	}

	/*derive prk_4e3m*/
	TRY(prk_derive(rc->static_dh_i, rc->suite, SALT_4e3m, &rc->th3,
		       &rc->prk_3e2m, &g_i, &c->y, rc->prk_4e3m.ptr));
	PRINT_ARRAY("prk_4e3m", rc->prk_4e3m.ptr, rc->prk_4e3m.len);

	TRY(signature_or_mac(VERIFY, rc->static_dh_i, &rc->suite, NULL, &pk,
			     &rc->prk_4e3m, &rc->th3, &id_cred_i, &cred_i,
			     &rc->ead, MAC_3, &sign_or_mac));

	/*TH4*/
	// ptxt3.len = ptxt3.len - get_aead_mac_len(rc->suite.edhoc_aead);
	TRY(th34_calculate(rc->suite.edhoc_hash, &rc->th3, &ptxt3, &cred_i,
			   &rc->th4));

	/*PRK_out*/
	TRY(edhoc_kdf(rc->suite.edhoc_hash, &rc->prk_4e3m, PRK_out, &rc->th4,
		      prk_out));
	return ok;
}

#ifdef MESSAGE_4
enum err msg4_gen(struct edhoc_responder_context *c, struct runtime_context *rc)
{
	/*Ciphertext 4 calculate*/
	BYTE_ARRAY_NEW(ctxt4, CIPHERTEXT4_SIZE, CIPHERTEXT4_SIZE);
#if PLAINTEXT4_SIZE != 0
	BYTE_ARRAY_NEW(ptxt4, PLAINTEXT4_SIZE, PLAINTEXT4_SIZE);
#else
	struct byte_array ptxt4 = BYTE_ARRAY_INIT(NULL, 0);
#endif

	TRY(ciphertext_gen(CIPHERTEXT4, &rc->suite, &NULL_ARRAY, &NULL_ARRAY,
			   &c->ead_4, &rc->prk_4e3m, &rc->th4, &ctxt4, &ptxt4));

	TRY(encode_bstr(&ctxt4, &rc->msg));

	PRINT_ARRAY("Message 4 ", rc->msg.ptr, rc->msg.len);
	return ok;
}
#endif // MESSAGE_4

enum err edhoc_responder_run_extended(
	struct edhoc_responder_context *c, struct cred_array *cred_i_array,
	struct byte_array *err_msg, struct byte_array *prk_out,
	struct byte_array *initiator_pub_key, struct byte_array *c_i_bytes,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead13))
{
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);

	/*receive message 1*/
	PRINT_MSG("waiting to receive message 1...\n");
	TRY(rx(c->sock, &rc.msg));

	/*create and send message 2*/
	TRY(msg2_gen(c, &rc, c_i_bytes));
	TRY(ead_process(c->params_ead_process, &rc.ead));
	TRY(tx(c->sock, &rc.msg));

	/*receive message 3*/
	PRINT_MSG("waiting to receive message 3...\n");
	rc.msg.len = sizeof(rc.msg_buf);
	TRY(rx(c->sock, &rc.msg));
	TRY(msg3_process(c, &rc, cred_i_array, prk_out, initiator_pub_key));
	TRY(ead_process(c->params_ead_process, &rc.ead));

	/*create and send message 4*/
#ifdef MESSAGE_4
	TRY(msg4_gen(c, &rc));
	TRY(tx(c->sock, &rc.msg));
#endif // MESSAGE_4
	return ok;
}

enum err edhoc_responder_run(
	struct edhoc_responder_context *c, struct cred_array *cred_i_array,
	struct byte_array *err_msg, struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead13))
{
	BYTE_ARRAY_NEW(c_i, C_I_SIZE, C_I_SIZE);
	return edhoc_responder_run_extended(c, cred_i_array, err_msg, prk_out,
					    &NULL_ARRAY, &c_i, tx, rx,
					    ead_process);
}
