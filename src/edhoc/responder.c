/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc.h"
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
#include "cbor/edhoc_decode_bstr_type.h"
#include "cbor/edhoc_decode_message_3.h"

#define CBOR_UINT_SINGLE_BYTE_UINT_MAX_VALUE (0x17)
#define CBOR_UINT_MULTI_BYTE_UINT_MAX_VALUE (0x17)
#define CBOR_BSTR_TYPE_MIN_VALUE (0x40)
#define CBOR_BSTR_TYPE_MAX_VALUE (0x57)

/**
 * @brief   Parses message 1
 * @param   msg1 buffer containing message 1
 * @param   msg1_len length of msg1
 * @param   method method
 * @param   suites_i
 * @param   suites_i_len length of suites_i
 * @param   g_x Public ephemeral key of the initiator
 * @param   g_x_len length of g_x
 * @param   c_i connection identifier of the initiator
 * @param   c_i_len length of c_i
 * @param   ad1 axillary data 1
 * @param   ad1_len length of ad1
 * @retval an err code
 */
static inline enum err msg1_parse(uint8_t *msg1, uint32_t msg1_len,
				  enum method_type *method, uint8_t *suites_i,
				  uint32_t *suites_i_len, uint8_t *g_x,
				  uint32_t *g_x_len, uint8_t *c_i,
				  uint32_t *c_i_len, uint8_t *ad1,
				  uint32_t *ad1_len)
{
	uint32_t i;
	struct message_1 m;
	size_t decode_len = 0;

	TRY_EXPECT(cbor_decode_message_1(msg1, msg1_len, &m, &decode_len),
		   true);

	/*METHOD*/
	*method = (enum method_type)m._message_1_METHOD;
	PRINTF("msg1 METHOD: %d\n", (int)*method);

	/*SUITES_I*/
	if (m._message_1_SUITES_I_choice == _message_1_SUITES_I_int) {
		/*the initiator supports only one suite*/
		suites_i[0] = (uint8_t)m._message_1_SUITES_I_int;
		*suites_i_len = 1;
	} else {
		/*the initiator supports more than one suite*/
		if (m._SUITES_I__suite_suite_count > *suites_i_len) {
			return suites_i_list_to_long;
		}

		for (i = 0; i < m._SUITES_I__suite_suite_count; i++) {
			suites_i[i] = (uint8_t)m._SUITES_I__suite_suite[i];
		}
		*suites_i_len = (uint32_t)m._SUITES_I__suite_suite_count;
	}
	PRINT_ARRAY("msg1 SUITES_I", suites_i, *suites_i_len);

	/*G_X*/
	TRY(_memcpy_s(g_x, *g_x_len, m._message_1_G_X.value,
		      (uint32_t)m._message_1_G_X.len));
	*g_x_len = (uint32_t)m._message_1_G_X.len;
	PRINT_ARRAY("msg1 G_X", g_x, *g_x_len);

	/*C_I*/
	if (m._message_1_C_I_choice == _message_1_C_I_int) {
		c_i[0] = (uint8_t)m._message_1_C_I_int;
		*c_i_len = 1;
	} else {

  TRY(_memcpy_s(c_i, *c_i_len, m._message_1_C_I_bstr.value,
              (uint32_t)m._message_1_C_I_bstr.len));
      *c_i_len = (uint32_t)m._message_1_C_I_bstr.len;

	}
	PRINT_ARRAY("msg1 C_I_raw", c_i, *c_i_len);

	/*ead_1*/
	if (m._message_1_ead_1_present) {
		TRY(_memcpy_s(ad1, *ad1_len, m._message_1_ead_1.value,
			      (uint32_t)m._message_1_ead_1.len));
		*ad1_len = (uint32_t)m._message_1_ead_1.len;
		PRINT_ARRAY("msg1 ead_1", ad1, *ad1_len);
	}
	return ok;
}

/**
 * @brief   checks if the selected (the first in the list received from the 
 *          initiator) ciphersute is supported
 * @param   selected the selected suite
 * @param   suites_r the list of suported ciphersuites
 * @retval  true if supported
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
 * @brief   Encodes message 2
 * @param   corr corelation parameter
 * @param   c_i Connection identifier of the initiator
 * @param   c_i_len length of c_i
 * @param   g_y public ephemeral DH key of the responder 
 * @param   g_y_len length of g_y
 * @param   c_r connection identifier of the responder
 * @param   c_r_len length of c_r
 * @param   ciphertext_2 the ciphertext
 * @param   ciphertext_2_len length of ciphertext_2
 * @param   msg2 the encoded message
 * @param   msg2_len length of msg2
 * @retval  an err error code
 */
static inline enum err msg2_encode(const uint8_t *g_y, uint32_t g_y_len,
				   uint8_t *c_r, uint32_t c_r_len,
				   const uint8_t *ciphertext_2,
				   uint32_t ciphertext_2_len, uint8_t *msg2,
				   uint32_t *msg2_len)
{
	size_t payload_len_out;
	struct m2 m;
	uint32_t g_y_ciphertext_2_len = g_y_len + ciphertext_2_len;
	TRY(check_buffer_size(G_Y_DEFAULT_SIZE + CIPHERTEXT2_DEFAULT_SIZE,
			      g_y_ciphertext_2_len));
	uint8_t g_y_ciphertext_2[G_Y_DEFAULT_SIZE + CIPHERTEXT2_DEFAULT_SIZE];

	memcpy(g_y_ciphertext_2, g_y, g_y_len);
	memcpy(g_y_ciphertext_2 + g_y_len, ciphertext_2, ciphertext_2_len);

	/*Encode g_y_ciphertext_2*/
	m._m2_G_Y_CIPHERTEXT_2.value = g_y_ciphertext_2;
	m._m2_G_Y_CIPHERTEXT_2.len = g_y_ciphertext_2_len;

	/*Encode C_R*/
	PRINT_ARRAY("C_R", c_r, c_r_len);
	if (c_r_len == 1 && (c_r[0] < 0x18 ||
			     (0x1F < c_r[0] && c_r[0] <= 0x37))) {
		m._m2_C_R_choice = _m2_C_R_int;
		TRY(decode_int(c_r, 1, &m._m2_C_R_int));
	} else {
		m._m2_C_R_choice = _m2_C_R_bstr;
		m._m2_C_R_bstr.value = c_r;
		m._m2_C_R_bstr.len = c_r_len;
	}

	TRY_EXPECT(cbor_encode_m2(msg2, *msg2_len, &m, &payload_len_out), true);
	*msg2_len = (uint32_t)payload_len_out;

	PRINT_ARRAY("message_2 (CBOR Sequence)", msg2, *msg2_len);
	return ok;
}

enum err msg2_gen(struct edhoc_responder_context *c, struct runtime_context *rc,
		  uint8_t *ead_1, uint32_t *ead_1_len, uint8_t *c_i_bytes, uint32_t *c_i_bytes_len)
{
	PRINT_ARRAY("message_1 (CBOR Sequence)", rc->msg, rc->msg_len);

	enum method_type method = INITIATOR_SK_RESPONDER_SK;
	uint8_t suites_i[SUITES_MAX];
	uint32_t suites_i_len = sizeof(suites_i);
	uint8_t g_x[G_X_DEFAULT_SIZE];
	uint32_t g_x_len = sizeof(g_x);
	uint8_t c_i[C_I_DEFAULT_SIZE];
	uint32_t c_i_len = sizeof(c_i);

	TRY(msg1_parse(rc->msg, rc->msg_len, &method, suites_i, &suites_i_len,
			       g_x, &g_x_len, c_i, &c_i_len, ead_1, ead_1_len));

	if ((NULL != c_i_bytes) && (NULL != c_i_bytes_len)) {
		TRY(_memcpy_s(c_i_bytes, *c_i_bytes_len, c_i, c_i_len));
		*c_i_bytes_len = c_i_len;
	}

	if (!(selected_suite_is_supported(suites_i[suites_i_len - 1],
					  &c->suites_r))) {
		// r = tx_err_msg(RESPONDER, method, c_i, c_i_len, NULL, 0,
		// 	       c->suites_r.ptr, c->suites_r.len);
		// if (r != ok) {
		// 	return r;
		// }
		/*After an error message is sent the protocol must be discontinued*/
		// PRINTF("After an error message is sent the protocol must be discontinued");
		return error_message_sent;
	}

	/*get cipher suite*/
	TRY(get_suite((enum suite_label)suites_i[suites_i_len - 1],
		      &rc->suite));

	bool static_dh_r;
	authentication_type_get(method, &rc->static_dh_i, &static_dh_r);

	/******************* create and send message 2*************************/
	uint8_t th2[HASH_DEFAULT_SIZE];
	uint32_t th2_len = get_hash_len(rc->suite.edhoc_hash);
	TRY(check_buffer_size(HASH_DEFAULT_SIZE, th2_len));
	TRY(hash(rc->suite.edhoc_hash, rc->msg, rc->msg_len, rc->msg1_hash));
	TRY(th2_calculate(rc->suite.edhoc_hash, rc->msg1_hash,
			  c->g_y.ptr, c->g_y.len, c->c_r.ptr, c->c_r.len, th2));

	/*calculate the DH shared secret*/
	uint8_t g_xy[ECDH_SECRET_DEFAULT_SIZE];
	TRY(shared_secret_derive(rc->suite.edhoc_ecdh, c->y.ptr, c->y.len, g_x,
				 g_x_len, g_xy));

	PRINT_ARRAY("G_XY (ECDH shared secret) ", g_xy, sizeof(g_xy));

	uint8_t PRK_2e[PRK_DEFAULT_SIZE];
	TRY(hkdf_extract(rc->suite.edhoc_hash, th2, th2_len, g_xy, sizeof(g_xy),
			 PRK_2e));
	PRINT_ARRAY("PRK_2e", PRK_2e, sizeof(PRK_2e));

	/*derive prk_3e2m*/
	TRY(prk_derive(static_dh_r, rc->suite, SALT_3e2m, th2, th2_len, PRK_2e,
		       sizeof(PRK_2e), g_x, g_x_len, c->r.ptr, c->r.len,
		       rc->prk_3e2m));
	PRINT_ARRAY("prk_3e2m", rc->prk_3e2m, rc->prk_3e2m_len);

	/*compute signature_or_MAC_2*/
	uint32_t sign_or_mac_2_len = get_signature_len(rc->suite.edhoc_sign);
	TRY(check_buffer_size(SIGNATURE_DEFAULT_SIZE, sign_or_mac_2_len));

	uint8_t sign_or_mac_2[SIGNATURE_DEFAULT_SIZE];
	TRY(signature_or_mac(GENERATE, static_dh_r, &rc->suite, c->sk_r.ptr,
			     c->sk_r.len, c->pk_r.ptr, c->pk_r.len,
			     rc->prk_3e2m, rc->prk_3e2m_len, th2, th2_len,
			     c->id_cred_r.ptr, c->id_cred_r.len, c->cred_r.ptr,
			     c->cred_r.len, c->ead_2.ptr, c->ead_2.len, MAC_2,
			     sign_or_mac_2, &sign_or_mac_2_len));

	/*compute ciphertext_2*/
	uint8_t plaintext_2[PLAINTEXT_DEFAULT_SIZE];
	uint32_t plaintext_2_len = sizeof(plaintext_2);
	uint8_t ciphertext_2[CIPHERTEXT2_DEFAULT_SIZE];
	uint32_t ciphertext_2_len = sizeof(ciphertext_2);
	TRY(ciphertext_gen(CIPHERTEXT2, &rc->suite, c->id_cred_r.ptr,
			   c->id_cred_r.len, sign_or_mac_2, sign_or_mac_2_len,
			   c->ead_2.ptr, c->ead_2.len, PRK_2e, sizeof(PRK_2e),
			   th2, th2_len, ciphertext_2, &ciphertext_2_len,
			   plaintext_2, &plaintext_2_len));

	/* Clear the message buffer. */
	memset(rc->msg, 0, rc->msg_len);
	rc->msg_len = sizeof(rc->msg);
	/*message 2 create*/
	TRY(msg2_encode(c->g_y.ptr, c->g_y.len, c->c_r.ptr, c->c_r.len,
				ciphertext_2, ciphertext_2_len, rc->msg,
				&rc->msg_len));

	TRY(th3_calculate(rc->suite.edhoc_hash, th2, th2_len, plaintext_2,
			  plaintext_2_len, c->cred_r.ptr, c->cred_r.len, rc->th3));

	return ok;
}

enum err msg3_process(struct edhoc_responder_context *c,
		      struct runtime_context *rc,
		      struct other_party_cred *cred_i_array,
		      uint16_t num_cred_i, uint8_t *ead_3, uint32_t *ead_3_len,
		      uint8_t *prk_out, uint32_t prk_out_len,
			  uint8_t *public_key, uint32_t *key_size)
{
	uint8_t ciphertext_3[CIPHERTEXT3_DEFAULT_SIZE];
	uint32_t ciphertext_3_len = sizeof(ciphertext_3);

	TRY(decode_byte_string(rc->msg, rc->msg_len, ciphertext_3,
			       &ciphertext_3_len));
	PRINT_ARRAY("CIPHERTEXT_3", ciphertext_3, ciphertext_3_len);

	uint8_t id_cred_i[ID_CRED_DEFAULT_SIZE];
	uint32_t id_cred_i_len = sizeof(id_cred_i);
	uint8_t sign_or_mac[SGN_OR_MAC_DEFAULT_SIZE];
	uint32_t sign_or_mac_len = sizeof(sign_or_mac);

	uint32_t plaintext3_len = ciphertext_3_len;
	uint8_t plaintext3[PLAINTEXT_DEFAULT_SIZE];
	TRY(check_buffer_size(PLAINTEXT_DEFAULT_SIZE, ciphertext_3_len));

	TRY(ciphertext_decrypt_split(
		CIPHERTEXT3, &rc->suite, id_cred_i, &id_cred_i_len, sign_or_mac,
		&sign_or_mac_len, ead_3, (uint32_t *)ead_3_len, rc->prk_3e2m,
		rc->prk_3e2m_len, rc->th3, rc->th3_len, ciphertext_3,
		ciphertext_3_len, plaintext3, plaintext3_len));

	/*check the authenticity of the initiator*/
	uint8_t cred_i[CRED_DEFAULT_SIZE];
	uint32_t cred_i_len = sizeof(cred_i);
	uint8_t pk[PK_DEFAULT_SIZE];
	uint32_t pk_len = sizeof(pk);
	uint8_t g_i[G_I_DEFAULT_SIZE];
	uint32_t g_i_len = sizeof(g_i);

	TRY(retrieve_cred(rc->static_dh_i, cred_i_array, num_cred_i, id_cred_i,
			  id_cred_i_len, cred_i, &cred_i_len, pk, &pk_len, g_i,
			  &g_i_len));
	PRINT_ARRAY("CRED_I", cred_i, cred_i_len);
	PRINT_ARRAY("pk", pk, pk_len);
	PRINT_ARRAY("g_i", g_i, g_i_len);

	/* Export public key. */
	if ((NULL != public_key) && (NULL != key_size)) {
		_memcpy_s(public_key, *key_size, pk, pk_len);
		*key_size = pk_len;
	}

	/*derive prk_4e3m*/
	TRY(prk_derive(rc->static_dh_i, rc->suite, SALT_4e3m, rc->th3,
		       rc->th3_len, rc->prk_3e2m, rc->prk_3e2m_len, g_i,
		       g_i_len, c->y.ptr, c->y.len, rc->prk_4e3m));
	PRINT_ARRAY("prk_4e3m", rc->prk_4e3m, rc->prk_4e3m_len);

	TRY(signature_or_mac(VERIFY, rc->static_dh_i, &rc->suite, NULL, 0, pk,
			     pk_len, rc->prk_4e3m, rc->prk_4e3m_len, rc->th3,
			     rc->th3_len, id_cred_i, id_cred_i_len, cred_i,
			     cred_i_len, ead_3, *(uint32_t *)ead_3_len, MAC_3,
			     sign_or_mac, &sign_or_mac_len));

	/*TH4*/
	TRY(th4_calculate(
		rc->suite.edhoc_hash, rc->th3, rc->th3_len, plaintext3,
		plaintext3_len - get_aead_mac_len(rc->suite.edhoc_aead),
		cred_i, cred_i_len,
		rc->th4));

	/*PRK_out*/
	TRY(edhoc_kdf(rc->suite.edhoc_hash, rc->prk_4e3m, rc->prk_4e3m_len,
		      PRK_out, rc->th4, rc->th4_len, prk_out_len, prk_out));
	return ok;
}

#ifdef EDHOC_MESSAGE_4_SUPPORTED
enum err msg4_gen(struct edhoc_responder_context *c, struct runtime_context *rc)
{
	/*Ciphertext 4 calculate*/
	uint8_t plaintext_4[PLAINTEXT_DEFAULT_SIZE];
	uint32_t plaintext_4_len = sizeof(plaintext_4);
	uint8_t ciphertext_4[CIPHERTEXT4_DEFAULT_SIZE];
	uint32_t ciphertext_4_len = sizeof(ciphertext_4);

	TRY(ciphertext_gen(CIPHERTEXT4, &rc->suite, NULL, 0, NULL, 0,
			   c->ead_4.ptr, c->ead_4.len, rc->prk_4e3m,
			   rc->prk_4e3m_len, rc->th4, rc->th4_len, ciphertext_4,
			   &ciphertext_4_len, plaintext_4, &plaintext_4_len));

	memset(rc->msg, 0, rc->msg_len);
	rc->msg_len = sizeof(rc->msg);
	TRY(encode_byte_string(ciphertext_4, ciphertext_4_len, rc->msg,
			       &rc->msg_len));

	PRINT_ARRAY("Message 4 ", rc->msg, rc->msg_len);
	return ok;
}
#endif // EDHOC_MESSAGE_4_SUPPORTED

enum err edhoc_responder_run_extended(
	struct edhoc_responder_context *c,
	struct other_party_cred *cred_i_array, uint16_t num_cred_i,
	uint8_t *err_msg, uint32_t *err_msg_len, uint8_t *ead_1,
	uint32_t *ead_1_len, uint8_t *ead_3, uint32_t *ead_3_len,
	uint8_t *prk_out, uint32_t prk_out_len,
	uint8_t *client_pub_key, uint32_t *client_pub_key_size,
	uint8_t *c_i_bytes, uint32_t *c_i_bytes_len,
	enum err (*tx)(void *sock, uint8_t *data, uint32_t data_len),
	enum err (*rx)(void *sock, uint8_t *data, uint32_t *data_len))
{
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);

	PRINT_MSG("waiting to receive message 1...\n");

	memset(rc.msg, 0, rc.msg_len);
	TRY(rx(c->sock, rc.msg, &rc.msg_len));
	if (MSG_MAX_SIZE < rc.msg_len) {
		return error_message_received;
	}
	TRY(msg2_gen(c, &rc, ead_1, ead_1_len, c_i_bytes, c_i_bytes_len));
	TRY(tx(c->sock, rc.msg, rc.msg_len));
	memset(rc.msg, 0, rc.msg_len);

	PRINT_MSG("waiting to receive message 3...\n");
	TRY(rx(c->sock, rc.msg, &rc.msg_len));
	if (MSG_MAX_SIZE < rc.msg_len) {
			return error_message_received;
	}
	TRY(msg3_process(c, &rc, cred_i_array, num_cred_i, ead_3, ead_3_len,
			 prk_out, prk_out_len, client_pub_key, client_pub_key_size));
#ifdef EDHOC_MESSAGE_4_SUPPORTED
	if (c->msg4) {
		TRY(msg4_gen(c, &rc));
		TRY(tx(c->sock, rc.msg, rc.msg_len));
	}
#endif // EDHOC_MESSAGE_4_SUPPORTED
	return ok;
}

enum err edhoc_responder_run(
	struct edhoc_responder_context *c,
	struct other_party_cred *cred_i_array, uint16_t num_cred_i,
	uint8_t *err_msg, uint32_t *err_msg_len, uint8_t *ead_1,
	uint32_t *ead_1_len, uint8_t *ead_3, uint32_t *ead_3_len,
	uint8_t *prk_out, uint32_t prk_out_len,
	enum err (*tx)(void *sock, uint8_t *data, uint32_t data_len),
	enum err (*rx)(void *sock, uint8_t *data, uint32_t *data_len))
{
	return edhoc_responder_run_extended(c, cred_i_array, num_cred_i,
					    err_msg, err_msg_len, ead_1,
					    ead_1_len, ead_3, ead_3_len,
					    prk_out, prk_out_len, NULL, NULL,
					    NULL, NULL, tx, rx);
}
