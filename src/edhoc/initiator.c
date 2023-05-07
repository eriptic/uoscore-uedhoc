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

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

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
 * @brief   Parses message 2
 * @param   c initiator context
 * @param   msg2 pointer to a buffer containing message 2 
 * @param   msg2_len the length of the raw message
 * @param   msg2_struct pointer to a structure for the parsed message
 * @param   err_msg pointer to an error message structure
 */
static inline enum err msg2_parse(uint8_t *msg2, uint32_t msg2_len,
				  uint8_t *g_y, uint32_t g_y_len, uint8_t *c_r,
				  uint32_t *c_r_len, uint8_t *ciphertext2,
				  uint32_t *ciphertext2_len)
{
	size_t decode_len = 0;
	struct m2 m;

	TRY_EXPECT(cbor_decode_m2(msg2, msg2_len, &m, &decode_len), true);
	TRY(_memcpy_s(g_y, g_y_len, m._m2_G_Y_CIPHERTEXT_2.value, g_y_len));
	PRINT_ARRAY("g_y", g_y, g_y_len);

	TRY(_memcpy_s(ciphertext2, *ciphertext2_len,
		      m._m2_G_Y_CIPHERTEXT_2.value + g_y_len,
		      (uint32_t)(m._m2_G_Y_CIPHERTEXT_2.len - g_y_len)));

	*ciphertext2_len = (uint32_t)m._m2_G_Y_CIPHERTEXT_2.len - g_y_len;
	PRINT_ARRAY("ciphertext2", ciphertext2, *ciphertext2_len);

	if (m._m2_C_R_choice == _m2_C_R_int) {
		TRY(encode_int(&m._m2_C_R_int, 1, c_r, c_r_len));
	} else {
		TRY(_memcpy_s(c_r, *c_r_len, m._m2_C_R_bstr.value,
			      (uint32_t)m._m2_C_R_bstr.len));
		*c_r_len = (uint32_t)m._m2_C_R_bstr.len;
	}
	PRINT_ARRAY("C_R_raw", c_r, *c_r_len);

	return ok;
}

enum err msg1_gen(const struct edhoc_initiator_context *c,
		  struct runtime_context *rc)
{
	struct message_1 m1;

	/*METHOD_CORR*/
	m1._message_1_METHOD = (int32_t)c->method;

	/*SUITES_I*/
	if (c->suites_i.len == 1) {
		/* only one suite, encode into int */
		m1._message_1_SUITES_I_choice = _message_1_SUITES_I_int;
		m1._message_1_SUITES_I_int = c->suites_i.ptr[0];
	} else if (c->suites_i.len > 1) {
		/* more than one suites, encode into array */
		m1._message_1_SUITES_I_choice = _SUITES_I__suite;
		m1._SUITES_I__suite_suite_count = c->suites_i.len;
		for (uint32_t i = 0; i < c->suites_i.len; i++) {
			m1._SUITES_I__suite_suite[i] = c->suites_i.ptr[i];
		}
	}

	/* G_X ephemeral public key */
	m1._message_1_G_X.value = c->g_x.ptr;
	m1._message_1_G_X.len = c->g_x.len;

	/* C_I connection ID  of the initiator*/
	PRINT_ARRAY("C_I", c->c_i.ptr, c->c_i.len);
	if (c->c_i.len == 1 &&
	    ((0x00 <= c->c_i.ptr[0] && c->c_i.ptr[0] < 0x18) ||
	     (0x1F < c->c_i.ptr[0] && c->c_i.ptr[0] <= 0x37))) {
		m1._message_1_C_I_choice = _message_1_C_I_int;
		TRY(decode_int(c->c_i.ptr, 1, &m1._message_1_C_I_int));
	} else {
		m1._message_1_C_I_choice = _message_1_C_I_bstr;
		m1._message_1_C_I_bstr.value = c->c_i.ptr;
		m1._message_1_C_I_bstr.len = c->c_i.len;
	}

	if (c->ead_1.len != 0) {
		/* ead_1 unprotected opaque auxiliary data */
		m1._message_1_ead_1.value = c->ead_1.ptr;
		m1._message_1_ead_1.len = c->ead_1.len;
		m1._message_1_ead_1_present = true;
	} else {
		m1._message_1_ead_1_present = 0;
	}

	size_t payload_len_out;
	TRY_EXPECT(cbor_encode_message_1(rc->msg, rc->msg_len, &m1,
					 &payload_len_out),
		   true);
	rc->msg_len = (uint32_t)payload_len_out;

	PRINT_ARRAY("message_1 (CBOR Sequence)", rc->msg, rc->msg_len);

	TRY(get_suite((enum suite_label)c->suites_i.ptr[c->suites_i.len - 1],
		      &rc->suite));
	/* Calculate hash of msg1 for TH2. */
	TRY(hash(rc->suite.edhoc_hash, rc->msg, rc->msg_len, rc->msg1_hash));
	return ok;
}

enum err msg3_gen(const struct edhoc_initiator_context *c,
		  struct runtime_context *rc,
		  struct other_party_cred *cred_r_array, uint16_t num_cred_r,
		  uint8_t *ead_2, uint32_t *ead_2_len, uint8_t *c_r,
		  uint32_t *c_r_len, uint8_t *prk_out, uint32_t prk_out_len)
{
	bool static_dh_i = false, static_dh_r = false;

	TRY(authentication_type_get(c->method, &static_dh_i, &static_dh_r));

	uint8_t g_y[G_Y_DEFAULT_SIZE];
	uint32_t g_y_len = get_ecdh_pk_len(rc->suite.edhoc_ecdh);

	uint8_t ciphertext[CIPHERTEXT2_DEFAULT_SIZE];
	uint32_t ciphertext_len = sizeof(ciphertext);
	uint8_t plaintext[PLAINTEXT_DEFAULT_SIZE];
	uint32_t plaintext_len = sizeof(plaintext);

	PRINT_ARRAY("message_2 (CBOR Sequence)", rc->msg, rc->msg_len);

	/* 
	* If an error message is received msg2_parse will return 
	* error_message_received. If this happens edhoc_initiator_run will 
	* return. Then the caller needs to examine SUITES_R in err_msg 
	* re-initialize the initiator and call edhoc_initiator_run again
	*/
	TRY(msg2_parse(rc->msg, rc->msg_len, g_y, g_y_len, c_r, c_r_len,
		       ciphertext, &ciphertext_len));
	// if (r == error_message_received) {
	// 	/*provide the error message to the caller*/
	// 	r = _memcpy_s(err_msg, *err_msg_len, msg2, msg2_len);
	// 	if (r != ok) {
	// 		return r;
	// 	}
	// 	*err_msg_len = msg2_len;
	// 	return error_message_received;
	// }

	/*calculate the DH shared secret*/
	uint8_t g_xy[ECDH_SECRET_DEFAULT_SIZE];
	TRY(shared_secret_derive(rc->suite.edhoc_ecdh, c->x.ptr, c->x.len, g_y,
				 g_y_len, g_xy));
	PRINT_ARRAY("G_XY (ECDH shared secret) ", g_xy, sizeof(g_xy));

	/*calculate th2*/
	uint8_t th2[HASH_DEFAULT_SIZE];
	uint32_t th2_len = get_hash_len(rc->suite.edhoc_hash);
	TRY(check_buffer_size(HASH_DEFAULT_SIZE, th2_len));

	TRY(th2_calculate(rc->suite.edhoc_hash, rc->msg1_hash, g_y, g_y_len,
			  c_r, *c_r_len, th2));
	PRINT_ARRAY("TH_2", th2, th2_len);

	/*calculate PRK_2e*/
	uint8_t PRK_2e[PRK_DEFAULT_SIZE];
	TRY(hkdf_extract(rc->suite.edhoc_hash, th2, th2_len, g_xy, sizeof(g_xy),
			 PRK_2e));
	PRINT_ARRAY("PRK_2e", PRK_2e, sizeof(PRK_2e));

	uint8_t sign_or_mac[SGN_OR_MAC_DEFAULT_SIZE];
	uint32_t sign_or_mac_len = sizeof(sign_or_mac);

	uint8_t id_cred_r[ID_CRED_DEFAULT_SIZE];
	uint32_t id_cred_r_len = sizeof(id_cred_r);

	plaintext_len = ciphertext_len;
	TRY(check_buffer_size(PLAINTEXT_DEFAULT_SIZE, plaintext_len));

	TRY(ciphertext_decrypt_split(
		CIPHERTEXT2, &rc->suite, id_cred_r, &id_cred_r_len, sign_or_mac,
		&sign_or_mac_len, ead_2, (uint32_t *)ead_2_len, PRK_2e,
		sizeof(PRK_2e), th2, th2_len, ciphertext, ciphertext_len,
		plaintext, plaintext_len));

	/*check the authenticity of the responder*/
	uint8_t cred_r[CRED_DEFAULT_SIZE];
	uint32_t cred_r_len = sizeof(cred_r);
	uint8_t pk[PK_DEFAULT_SIZE];
	uint32_t pk_len = sizeof(pk);
	uint8_t g_r[G_R_DEFAULT_SIZE];
	uint32_t g_r_len = sizeof(g_r);

	TRY(retrieve_cred(static_dh_r, cred_r_array, num_cred_r, id_cred_r,
			  id_cred_r_len, cred_r, &cred_r_len, pk, &pk_len, g_r,
			  &g_r_len));
	PRINT_ARRAY("CRED_R", cred_r, cred_r_len);
	PRINT_ARRAY("pk", pk, pk_len);
	PRINT_ARRAY("g_r", g_r, g_r_len);

	/*derive prk_3e2m*/
	uint8_t PRK_3e2m[PRK_DEFAULT_SIZE];
	TRY(prk_derive(static_dh_r, rc->suite, SALT_3e2m, th2, th2_len, PRK_2e,
		       sizeof(PRK_2e), g_r, g_r_len, c->x.ptr, c->x.len,
		       PRK_3e2m));
	PRINT_ARRAY("prk_3e2m", PRK_3e2m, sizeof(PRK_3e2m));
	//todo why static_dh_r?
	uint32_t ead_len = (ead_2_len == NULL) ? 0 : *(uint32_t *)ead_2_len;
	TRY(signature_or_mac(VERIFY, static_dh_r, &rc->suite, NULL, 0, pk,
			     pk_len, PRK_3e2m, sizeof(PRK_3e2m), th2, th2_len,
			     id_cred_r, id_cred_r_len, cred_r, cred_r_len,
			     ead_2, ead_len, MAC_2, sign_or_mac,
			     &sign_or_mac_len));

	/********msg3 create and send**************************************/
	uint8_t th3[HASH_DEFAULT_SIZE];
	uint32_t th3_len = get_hash_len(rc->suite.edhoc_hash);
	TRY(check_buffer_size(HASH_DEFAULT_SIZE, th3_len));
	TRY(th3_calculate(rc->suite.edhoc_hash, (uint8_t *)&th2, th2_len,
			  plaintext, plaintext_len, cred_r, cred_r_len, th3));

	/*derive prk_4e3m*/
	TRY(prk_derive(static_dh_i, rc->suite, SALT_4e3m, th3, th3_len,
		       (uint8_t *)&PRK_3e2m, sizeof(PRK_3e2m), g_y, g_y_len,
		       c->i.ptr, c->i.len, rc->prk_4e3m));
	PRINT_ARRAY("prk_4e3m", rc->prk_4e3m, rc->prk_4e3m_len);

	/*calculate Signature_or_MAC_3*/
	uint32_t sign_or_mac_3_len = get_signature_len(rc->suite.edhoc_sign);
	uint8_t sign_or_mac_3[SIGNATURE_DEFAULT_SIZE];

	TRY(signature_or_mac(GENERATE, static_dh_i, &rc->suite, c->sk_i.ptr,
			     c->sk_i.len, c->pk_i.ptr, c->pk_i.len,
			     rc->prk_4e3m, rc->prk_4e3m_len, th3, th3_len,
			     c->id_cred_i.ptr, c->id_cred_i.len, c->cred_i.ptr,
			     c->cred_i.len, c->ead_3.ptr, c->ead_3.len, MAC_3,
			     sign_or_mac_3, &sign_or_mac_3_len));

	plaintext_len = sizeof(plaintext);
	ciphertext_len = sizeof(ciphertext);

	TRY(ciphertext_gen(CIPHERTEXT3, &rc->suite, c->id_cred_i.ptr,
			   c->id_cred_i.len, sign_or_mac_3, sign_or_mac_3_len,
			   c->ead_3.ptr, c->ead_3.len, PRK_3e2m,
			   sizeof(PRK_3e2m), th3, th3_len, ciphertext,
			   &ciphertext_len, plaintext, &plaintext_len));

	/*massage 3 create and send*/
	TRY(check_buffer_size(CIPHERTEXT3_DEFAULT_SIZE,
			      ciphertext_len + ENCODING_OVERHEAD));

	memset(rc->msg, 0, rc->msg_len);
	rc->msg_len = sizeof(rc->msg);
	TRY(encode_byte_string(ciphertext, ciphertext_len, rc->msg,
			       &rc->msg_len));
	PRINT_ARRAY("msg3", rc->msg, rc->msg_len);

	/*TH4*/
	TRY(th4_calculate(rc->suite.edhoc_hash, th3, th3_len, plaintext,
			  plaintext_len, c->cred_i.ptr, c->cred_i.len,
			  rc->th4));

	/*PRK_out*/
	TRY(edhoc_kdf(rc->suite.edhoc_hash, rc->prk_4e3m, rc->prk_4e3m_len,
		      PRK_out, rc->th4, rc->th4_len, prk_out_len, prk_out));
	return ok;
}

#ifdef EDHOC_MESSAGE_4_SUPPORTED
enum err msg4_process(struct runtime_context *rc, uint8_t *ead_4,
		      uint32_t *ead_4_len)
{
	PRINT_ARRAY("message_4 (CBOR Sequence)", rc->msg, rc->msg_len);

	uint8_t ciphertext_4[CIPHERTEXT4_DEFAULT_SIZE];
	uint32_t ciphertext_4_len = sizeof(ciphertext_4);
	TRY(decode_byte_string(rc->msg, rc->msg_len, ciphertext_4,
			       &ciphertext_4_len));
	PRINT_ARRAY("ciphertext_4", ciphertext_4, ciphertext_4_len);

	uint32_t plaintext4_len = ciphertext_4_len;
	uint8_t plaintext4[PLAINTEXT_DEFAULT_SIZE];
	TRY(check_buffer_size(PLAINTEXT_DEFAULT_SIZE, ciphertext_4_len));

	TRY(ciphertext_decrypt_split(CIPHERTEXT4, &rc->suite, NULL, 0, NULL, 0,
				     ead_4, (uint32_t *)ead_4_len, rc->prk_4e3m,
				     rc->prk_4e3m_len, rc->th4, rc->th4_len,
				     ciphertext_4, ciphertext_4_len, plaintext4,
				     plaintext4_len));
	return ok;
}
#endif // EDHOC_MESSAGE_4_SUPPORTED

enum err edhoc_initiator_run_extended(
	const struct edhoc_initiator_context *c,
	struct other_party_cred *cred_r_array, uint16_t num_cred_r,
	uint8_t *err_msg, uint32_t *err_msg_len, uint8_t *ead_2,
	uint32_t *ead_2_len, uint8_t *ead_4, uint32_t *ead_4_len,
	uint8_t *c_r_bytes, uint32_t *c_r_bytes_len, uint8_t *prk_out,
	uint32_t prk_out_len,
	enum err (*tx)(void *sock, uint8_t *data, uint32_t data_len),
	enum err (*rx)(void *sock, uint8_t *data, uint32_t *data_len))
{
	struct runtime_context rc = { 0 };
	runtime_context_init(&rc);

	TRY(msg1_gen(c, &rc));
	TRY(tx(c->sock, rc.msg, rc.msg_len));
	memset(rc.msg, 0, rc.msg_len);
	rc.msg_len = sizeof(rc.msg);

	PRINT_MSG("waiting to receive message 2...\n");
	TRY(rx(c->sock, rc.msg, &rc.msg_len));
	TRY(msg3_gen(c, &rc, cred_r_array, num_cred_r, ead_2, ead_2_len,
		     c_r_bytes, c_r_bytes_len, prk_out, prk_out_len));
	TRY(tx(c->sock, rc.msg, rc.msg_len));

#ifdef EDHOC_MESSAGE_4_SUPPORTED
	if (c->msg4) {
		PRINT_MSG("waiting to receive message 4...\n");
		TRY(rx(c->sock, rc.msg, &rc.msg_len));
		TRY(msg4_process(&rc, ead_4, ead_4_len));
	}
#endif // EDHOC_MESSAGE_4_SUPPORTED
	return ok;
}

enum err edhoc_initiator_run(
	const struct edhoc_initiator_context *c,
	struct other_party_cred *cred_r_array, uint16_t num_cred_r,
	uint8_t *err_msg, uint32_t *err_msg_len, uint8_t *ead_2,
	uint32_t *ead_2_len, uint8_t *ead_4, uint32_t *ead_4_len,
	uint8_t *prk_out, uint32_t prk_out_len,
	enum err (*tx)(void *sock, uint8_t *data, uint32_t data_len),
	enum err (*rx)(void *sock, uint8_t *data, uint32_t *data_len))
{
	uint8_t c_r[C_R_DEFAULT_SIZE];
	uint32_t c_r_len = sizeof(c_r);

	return edhoc_initiator_run_extended(c, cred_r_array, num_cred_r,
					    err_msg, err_msg_len, ead_2,
					    ead_2_len, ead_4, ead_4_len, c_r,
					    &c_r_len, prk_out, prk_out_len, tx,
					    rx);
}
