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
#include <stdlib.h>
#include <string.h>

#include "oscore.h"

#include "oscore/aad.h"
#include "oscore/nonce.h"
#include "oscore/oscore_coap.h"
#include "oscore/oscore_hkdf_info.h"
#include "oscore/security_context.h"
#include "oscore/nvm.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"
#include "common/unit_test.h"

/**
 * @brief       Common derive procedure used to derive the Common IV and 
 *              Sender / Recipient Keys
 * @param cc    pointer to the common context
 * @param id    empty array for Common IV, sender / recipient ID for keys
 * @param type  IV for Common IV, KEY for Sender / Recipient Keys
 * @param out   out-array. Must be initialized
 * @return      err
 */
STATIC enum err derive(struct common_context *cc, struct byte_array *id,
		       enum derive_type type, struct byte_array *out)
{
	BYTE_ARRAY_NEW(info, MAX_INFO_LEN, MAX_INFO_LEN);
	TRY(oscore_create_hkdf_info(id, &cc->id_context, cc->aead_alg, type,
				    &info));

	PRINT_ARRAY("info struct", info.ptr, info.len);

	switch (cc->kdf) {
	case OSCORE_SHA_256:
		TRY(hkdf_sha_256(&cc->master_secret, &cc->master_salt, &info,
				 out));
		break;
	default:
		return oscore_unknown_hkdf;
		break;
	}
	return ok;
}

/**
 * @brief    Derives the Common IV 
 * @param    cc    pointer to the common context
 * @return   err
 */
static enum err derive_common_iv(struct common_context *cc)
{
	TRY(derive(cc, &EMPTY_ARRAY, IV, &cc->common_iv));
	PRINT_ARRAY("Common IV", cc->common_iv.ptr, cc->common_iv.len);
	return ok;
}

/**
 * @brief    Derives the Sender Key 
 * @param    cc    pointer to the common context
 * @param    sc    pointer to the sender context
 * @return   err
 */
static enum err derive_sender_key(struct common_context *cc,
				  struct sender_context *sc)
{
	TRY(derive(cc, &sc->sender_id, KEY, &sc->sender_key));
	PRINT_ARRAY("Sender Key", sc->sender_key.ptr, sc->sender_key.len);
	return ok;
}

/**
 * @brief    Derives the Recipient Key 
 * @param    cc    pointer to the common context
 * @param    sc    pointer to the recipient context
 * @return   err
 */
static enum err derive_recipient_key(struct common_context *cc,
				     struct recipient_context *rc)
{
	TRY(derive(cc, &rc->recipient_id, KEY, &rc->recipient_key));

	PRINT_ARRAY("Recipient Key", rc->recipient_key.ptr,
		    rc->recipient_key.len);
	return ok;
}

enum err oscore_context_init(struct oscore_init_params *params,
			     struct context *c)
{
	/*derive common context************************************************/

	if (params->aead_alg != OSCORE_AES_CCM_16_64_128) {
		return oscore_invalid_algorithm_aead;
	} else {
		c->cc.aead_alg =
			OSCORE_AES_CCM_16_64_128; /*that's the default*/
	}

	if (params->hkdf != OSCORE_SHA_256) {
		return oscore_invalid_algorithm_hkdf;
	} else {
		c->cc.kdf = OSCORE_SHA_256; /*that's the default*/
	}

	c->cc.master_secret = params->master_secret;
	c->cc.master_salt = params->master_salt;
	c->cc.id_context = params->id_context;
	c->cc.common_iv.len = sizeof(c->cc.common_iv_buf);
	c->cc.common_iv.ptr = c->cc.common_iv_buf;
	TRY(derive_common_iv(&c->cc));

	/*derive Recipient Context*********************************************/
	c->rc.notification_num_initialized = false;
	server_replay_window_init(&c->rc.replay_window);
	c->rc.recipient_id.len = params->recipient_id.len;
	c->rc.recipient_id.ptr = c->rc.recipient_id_buf;
	memcpy(c->rc.recipient_id.ptr, params->recipient_id.ptr,
	       params->recipient_id.len);
	c->rc.recipient_key.len = sizeof(c->rc.recipient_key_buf);
	c->rc.recipient_key.ptr = c->rc.recipient_key_buf;
	TRY(derive_recipient_key(&c->cc, &c->rc));

	/*derive Sender Context************************************************/
	c->sc.sender_id = params->sender_id;
	c->sc.sender_key.len = sizeof(c->sc.sender_key_buf);
	c->sc.sender_key.ptr = c->sc.sender_key_buf;
	c->sc.ssn_in_nvm = !params->fresh_master_secret_salt;
	TRY(ssn_init(&c->sc.sender_id, &c->cc.id_context, &c->sc.ssn,
		     c->sc.ssn_in_nvm));
	TRY(derive_sender_key(&c->cc, &c->sc));

	/*set up the request response context**********************************/
	c->rrc.nonce.len = sizeof(c->rrc.nonce_buf);
	c->rrc.nonce.ptr = c->rrc.nonce_buf;
	c->rrc.request_kid.len = sizeof(c->rrc.request_kid_buf);
	c->rrc.request_kid.ptr = c->rrc.request_kid_buf;
	c->rrc.request_piv.len = sizeof(c->rrc.request_piv_buf);
	c->rrc.request_piv.ptr = c->rrc.request_piv_buf;
	c->rrc.echo_opt_val.len = sizeof(c->rrc.echo_opt_val_buf);
	c->rrc.echo_opt_val.ptr = c->rrc.echo_opt_val_buf;
	c->rrc.echo_state_machine = ECHO_REBOOT;
	return ok;
}

enum err update_request_piv_request_kid(struct context *c,
					struct byte_array *piv,
					struct byte_array *kid)
{
	TRY(byte_array_cpy(&c->rrc.request_kid, kid, MAX_KID_LEN));
	TRY(byte_array_cpy(&c->rrc.request_piv, piv, MAX_PIV_LEN));
	return ok;
}

enum err ssn2piv(uint64_t ssn, struct byte_array *piv)
{
	uint8_t *p = (uint8_t *)&ssn;

	for (int8_t i = 7; i >= 0; i--) {
		if (*(p + i) > 0) {
			TRY(_memcpy_s(piv->ptr, MAX_PIV_LEN, p,
				      (uint32_t)(i + 1)));
			piv->len = (uint32_t)(i + 1);
			PRINT_ARRAY("PIV", piv->ptr, piv->len);
			return ok;
		}
	}

	/*if the sender seq number is 0 piv has value 0 and length 1*/
	*piv->ptr = 0;
	piv->len = 1;
	PRINT_ARRAY("PIV", piv->ptr, piv->len);
	return ok;
}

enum err piv2ssn(struct byte_array *piv, uint64_t *ssn)
{
	if ((NULL == ssn) || (NULL == piv)) {
		return wrong_parameter;
	}
	uint64_t result = 0;
	for (uint32_t pos = 0; pos < piv->len; pos++) {
		result += (uint64_t)(piv->ptr[pos]) << (8 * pos);
	}
	*ssn = result;
	return ok;
}
