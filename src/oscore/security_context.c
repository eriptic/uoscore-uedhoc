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

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

/**
 * @brief       Common derive procedure used to derive the Common IV and 
 *              Sender / Recipient Keys
 * @param cc    pointer to the common context
 * @param id    empty array for Common IV, sender / recipient ID for keys
 * @param type  IV for Common IV, KEY for Sender / Recipient Keys
 * @param out   out-array. Must be initialized
 * @return      err
 */
static enum err derive(struct common_context *cc, struct byte_array *id,
		       enum derive_type type, struct byte_array *out)
{
	uint8_t info_bytes[MAX_INFO_LEN];
	struct byte_array info = {
		.len = sizeof(info_bytes),
		.ptr = info_bytes,
	};

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

enum err context_update(enum dev_type dev, struct o_coap_option *options,
			uint16_t opt_num, struct byte_array *new_piv,
			struct byte_array *new_kid_context, struct context *c)
{
	if (dev == SERVER) {
		/**************************************************************/
		/*update PIV*/
		TRY(_memcpy_s(c->rrc.piv.ptr, MAX_PIV_LEN, new_piv->ptr,
			      new_piv->len));

		c->rrc.piv.len = new_piv->len;

		/**************************************************************/
		/*update Sender Key, Recipient Key and Common IV if KID context 
		defers from the ID Context*/
		if (!array_equals(&c->cc.id_context, new_kid_context)) {
			/*if the ID Context is equal to the KID_context (the 
			ID_context received with the oscore option) no update 
			of Sender/recipient keys and Common IV required)*/

			/*update KID Context*/
			TRY(_memcpy_s(c->rrc.kid_context.ptr,
				      MAX_KID_CONTEXT_LEN, new_kid_context->ptr,
				      new_kid_context->len));

			c->rrc.kid_context.len = new_kid_context->len;

			TRY(_memcpy_s(
				c->cc.id_context.ptr, c->cc.id_context.len,
				new_kid_context->ptr, new_kid_context->len));

			c->cc.id_context.len = new_kid_context->len;

			PRINT_MSG("Common Context Updated*****************\n");
			TRY(derive_common_iv(&c->cc));
			TRY(derive_sender_key(&c->cc, &c->sc));
			TRY(derive_recipient_key(&c->cc, &c->rc));
		}
	}
	/**********************************************************************/
	/*calculate nonce*/
	TRY(create_nonce(&c->rrc.kid, &c->rrc.piv, &c->cc.common_iv,
			 &c->rrc.nonce));

	/**********************************************************************/
	/*calculate AAD*/
	return create_aad(options, opt_num, c->cc.aead_alg, &c->rrc.kid,
			  &c->rrc.piv, &c->rrc.aad);
}

enum err oscore_context_init(struct oscore_init_params *params,
			     struct context *c)
{
	if (params->dev_type == CLIENT) {
		PRINT_MSG(
			"\n\n\nClient context initialization****************\n");
	} else {
		PRINT_MSG(
			"\n\n\nServer context initialization****************\n");
	}

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
	c->rc.replay_window_len = REPLAY_WINDOW_LEN;
	memset(c->rc.replay_window, 0,
	       sizeof(c->rc.replay_window[0]) * c->rc.replay_window_len);
	c->rc.recipient_id = params->recipient_id;
	c->rc.recipient_key.len = sizeof(c->rc.recipient_key_buf);
	c->rc.recipient_key.ptr = c->rc.recipient_key_buf;
	TRY(derive_recipient_key(&c->cc, &c->rc));

	/*derive Sender Context************************************************/
	c->sc.sender_id = params->sender_id;
	c->sc.sender_key.len = sizeof(c->sc.sender_key_buf);
	c->sc.sender_key.ptr = c->sc.sender_key_buf;
	TRY(derive_sender_key(&c->cc, &c->sc));
	c->sc.sender_seq_num = 0;

	/*set up the request response context**********************************/
	c->rrc.nonce.len = sizeof(c->rrc.nonce_buf);
	c->rrc.nonce.ptr = c->rrc.nonce_buf;

	c->rrc.aad.len = sizeof(c->rrc.aad_buf);
	c->rrc.aad.ptr = c->rrc.aad_buf;

	c->rrc.piv.len = sizeof(c->rrc.piv_buf);
	c->rrc.piv.ptr = c->rrc.piv_buf;

	c->rrc.kid_context.len = sizeof(c->rrc.kid_context_buf);
	c->rrc.kid_context.ptr = c->rrc.kid_context_buf;

	c->rrc.kid.len = sizeof(c->rrc.kid_buf);
	c->rrc.kid.ptr = c->rrc.kid_buf;

	if (params->dev_type == CLIENT) {
		TRY(_memcpy_s(c->rrc.kid_context.ptr, c->rrc.kid_context.len,
			      params->id_context.ptr, params->id_context.len));
		c->rrc.kid_context.len = params->id_context.len;
		TRY(_memcpy_s(c->rrc.kid.ptr, c->rrc.kid.len,
			      params->sender_id.ptr, params->sender_id.len));
		c->rrc.kid.len = params->sender_id.len;

		PRINT_ARRAY("KID context", c->rrc.kid_context.ptr,
			    c->rrc.kid_context.len);
	} else {
		TRY(_memcpy_s(c->rrc.kid.ptr, c->rrc.kid.len,
			      params->recipient_id.ptr,
			      params->recipient_id.len));
		c->rrc.kid.len = params->recipient_id.len;
	}
	PRINT_ARRAY("KID", c->rrc.kid.ptr, c->rrc.kid.len);
	return ok;
}

//todo: how big is piv? 5 byte= 40 bit -> in that case the sender sequence number needs to loop at the value of 2^40 -1 !!! -> uint8_t is sufficient for the sender sequence number.
enum err sender_seq_num2piv(uint64_t ssn, struct byte_array *piv)
{
	uint8_t *p = (uint8_t *)&ssn;

	//todo here we can start at 4?
	for (int8_t i = 7; i >= 0; i--) {
		if (*(p + i) > 0) {
			TRY(_memcpy_s(piv->ptr, MAX_PIV_LEN, p,
				      (uint32_t)(i + 1)));
			piv->len = (uint32_t)(i + 1);
			return ok;
		}
	}

	/*if the sender seq number is 0 piv has value 0 and length 1*/
	*piv->ptr = 0;
	piv->len = 1;
	return ok;
}
