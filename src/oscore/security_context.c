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
#include "oscore/oscore_interactions.h"
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
	struct nvm_key_t nvm_key = { .sender_id = c->sc.sender_id,
				     .recipient_id = c->rc.recipient_id,
				     .id_context = c->cc.id_context };

	TRY(ssn_init(&nvm_key, &c->sc.ssn, params->fresh_master_secret_salt));
	TRY(derive_sender_key(&c->cc, &c->sc));

	/*set up the request response context**********************************/
	oscore_interactions_init(c->rrc.interactions);
	c->rrc.nonce.len = sizeof(c->rrc.nonce_buf);
	c->rrc.nonce.ptr = c->rrc.nonce_buf;
	c->rrc.echo_opt_val.len = sizeof(c->rrc.echo_opt_val_buf);
	c->rrc.echo_opt_val.ptr = c->rrc.echo_opt_val_buf;

	/* no ECHO challenge needed if the context is fresh */
	c->rrc.echo_state_machine =
		(params->fresh_master_secret_salt ? ECHO_SYNCHRONIZED :
						    ECHO_REBOOT);

	return ok;
}

enum err check_context_freshness(struct context *c)
{
	if (NULL == c) {
		return wrong_parameter;
	}

	/* "If the Sender Sequence Number exceeds the maximum, the endpoint MUST NOT
	   process any more messages with the given Sender Context."
	   For more info, refer to RFC 8613 p. 7.2.1. */
	if (c->sc.ssn >= OSCORE_SSN_OVERFLOW_VALUE) {
		PRINT_MSG(
			"Sender Sequence Number reached its limit. New security context must be established.\n");
		return oscore_ssn_overflow;
	}
	return ok;
}

enum err ssn2piv(uint64_t ssn, struct byte_array *piv)
{
	if ((NULL == piv) || (NULL == piv->ptr) ||
	    (ssn > MAX_PIV_FIELD_VALUE)) {
		return wrong_parameter;
	}

	static uint8_t tmp_piv[MAX_PIV_LEN];
	uint8_t len = 0;
	while (ssn > 0) {
		tmp_piv[len] = (uint8_t)(ssn & 0xFF);
		len++;
		ssn >>= 8;
	}

	if (len == 0) {
		//if the sender seq number is 0 piv has value 0 and length 1
		piv->ptr[0] = 0;
		piv->len = 1;
	} else {
		//PIV is encoded in big endian
		for (uint8_t pos = 0; pos < len; pos++) {
			piv->ptr[pos] = tmp_piv[len - 1 - pos];
		}
		piv->len = len;
	}
	return ok;
}

enum err piv2ssn(struct byte_array *piv, uint64_t *ssn)
{
	if ((NULL == ssn) || (NULL == piv)) {
		return wrong_parameter;
	}

	uint8_t *value = piv->ptr;
	uint32_t len = piv->len;
	if (len > MAX_PIV_LEN) {
		return wrong_parameter;
	}

	uint64_t result = 0;
	if (NULL != value) {
		//PIV is encoded in big endian
		for (uint32_t pos = 0; pos < len; pos++) {
			result += (uint64_t)(value[pos])
				  << (8 * (len - 1 - pos));
		}
	}
	*ssn = result;
	return ok;
}
