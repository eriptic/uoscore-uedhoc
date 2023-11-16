/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdint.h>
#include <stdio.h>
#include <string.h>

#include "oscore.h"

#include "oscore/aad.h"
#include "oscore/oscore_coap.h"
#include "oscore/nonce.h"
#include "oscore/option.h"
#include "oscore/oscore_cose.h"
#include "oscore/security_context.h"
#include "oscore/nvm.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"
#include "common/unit_test.h"

/**
 * @brief Extract input CoAP options into E(encrypted) and U(unprotected)
 * @param in_o_coap: input CoAP packet
 * @param e_options: output pointer to E-options
 * @param e_options_cnt: count number of output E-options
 * @param e_options_len: Byte string length of all E-options, which will be used when forming E-options into plaintext
 * @param U_options: output pointer to U-options
 * @param U_options_cnt: count number of output U-options
 * @return err
 *
 */
STATIC enum err inner_outer_option_split(struct o_coap_packet *in_o_coap,
					 struct o_coap_option *e_options,
					 uint8_t *e_options_cnt,
					 uint16_t *e_options_len,
					 struct o_coap_option *U_options,
					 uint8_t *U_options_cnt)
{
	enum err r = ok;

	/* Initialize to 0 */
	*e_options_len = 0;

	uint8_t temp_option_nr = 0;
	uint16_t temp_len = 0;
	uint8_t temp_E_option_delta_sum = 0;
	uint8_t temp_U_option_delta_sum = 0;

	if (MAX_OPTION_COUNT < in_o_coap->options_cnt) {
		return too_many_options;
	}

	for (uint8_t i = 0; i < in_o_coap->options_cnt; i++) {
		uint8_t extra_bytes =
			opt_extra_bytes(in_o_coap->options[i].delta) +
			opt_extra_bytes(in_o_coap->options[i].len);

		temp_option_nr =
			(uint8_t)(temp_option_nr + in_o_coap->options[i].delta);
		temp_len = in_o_coap->options[i].len;

		/* process special options, see 4.1.3 in RFC8613*/
		/* if the option does not need special processing just put it in the 
		E or U array*/

		switch (temp_option_nr) {
		case OBSERVE:
			/*An observe option in an a CoAP packet is transformed to an inner
			and outer option in a OSCORE packet.*/

			/*
			* Inner option has value NULL if notification or the original value 
			* in the coap packet if registration/cancellation.
			*/
			e_options[*e_options_cnt].delta = (uint16_t)(
				temp_option_nr - temp_E_option_delta_sum);
			if (is_request(in_o_coap)) {
				/*registrations/cancellations are requests */
				e_options[*e_options_cnt].len = temp_len;
				e_options[*e_options_cnt].value =
					in_o_coap->options[i].value;

				/* Add option header length and value length */
				(*e_options_len) =
					(uint16_t)((*e_options_len) + 1 +
						   extra_bytes + temp_len);
			} else {
				/*notifications are responses*/
				e_options[*e_options_cnt].len = 0;
				e_options[*e_options_cnt].value = NULL;

				/* since the option value has length 0, we add 1 for the option header which is always there */
				(*e_options_len)++;
			}

			e_options[*e_options_cnt].option_number =
				temp_option_nr;

			/* Update delta sum of E-options */
			temp_E_option_delta_sum =
				(uint8_t)(temp_E_option_delta_sum +
					  e_options[*e_options_cnt].delta);

			/* Increment E-options count */
			(*e_options_cnt)++;

			/*
			*outer option (value as in the original coap packet
			*/
			U_options[*U_options_cnt].delta = (uint16_t)(
				temp_option_nr - temp_U_option_delta_sum);
			U_options[*U_options_cnt].len = temp_len;
			U_options[*U_options_cnt].value =
				in_o_coap->options[i].value;
			U_options[*U_options_cnt].option_number =
				temp_option_nr;

			/* Update delta sum of E-options */
			temp_U_option_delta_sum =
				(uint8_t)(temp_U_option_delta_sum +
					  U_options[*U_options_cnt].delta);

			/* Increment E-options count */
			(*U_options_cnt)++;

			break;

		default:
			/* check delta, whether current option U or E */
			if (is_class_e(temp_option_nr) == 1) {
				/* E-options, which will be copied in plaintext to be encrypted*/
				e_options[*e_options_cnt].delta =
					(uint16_t)(temp_option_nr -
						   temp_E_option_delta_sum);
				e_options[*e_options_cnt].len = temp_len;
				e_options[*e_options_cnt].value =
					in_o_coap->options[i].value;
				e_options[*e_options_cnt].option_number =
					temp_option_nr;

				/* Update delta sum of E-options */
				temp_E_option_delta_sum = (uint8_t)(
					temp_E_option_delta_sum +
					e_options[*e_options_cnt].delta);

				/* Increment E-options count */
				(*e_options_cnt)++;
				/* Add option header length and value length */
				(*e_options_len) =
					(uint16_t)((*e_options_len) + 1 +
						   extra_bytes + temp_len);
			} else {
				/* U-options */
				U_options[*U_options_cnt].delta =
					(uint16_t)(temp_option_nr -
						   temp_U_option_delta_sum);
				U_options[*U_options_cnt].len = temp_len;
				U_options[*U_options_cnt].value =
					in_o_coap->options[i].value;
				U_options[*U_options_cnt].option_number =
					temp_option_nr;

				/* Update delta sum of E-options */
				temp_U_option_delta_sum = (uint8_t)(
					temp_U_option_delta_sum +
					U_options[*U_options_cnt].delta);

				/* Increment E-options count */
				(*U_options_cnt)++;
			}
			break;
		}
	}
	return r;
}

/**
 * @brief Build up plaintext which should be encrypted and protected
 * @param in_o_coap: input CoAP packet that will be analyzed
 * @param E_options: E-options, which should be protected
 * @param E_options_cnt: count number of E-options
 * @param plaintext: output plaintext, which will be encrypted
 * @return err
 *
 */
static inline enum err plaintext_setup(struct o_coap_packet *in_o_coap,
				       struct o_coap_option *E_options,
				       uint8_t E_options_cnt,
				       struct byte_array *plaintext)
{
	uint8_t *temp_plaintext_ptr = plaintext->ptr;

	/* Add code to plaintext */
	*temp_plaintext_ptr = in_o_coap->header.code;

	/* Calculate the maximal length of all options, i.e. all options 
	have two bytes extra delta and length */
	uint16_t e_opt_serial_len = 0;
	for (uint8_t i = 0; i < E_options_cnt; i++) {
		e_opt_serial_len = (uint16_t)(e_opt_serial_len + 1 + 2 + 2 +
					      E_options[i].len);
	}
	/* Setup buffer */
	BYTE_ARRAY_NEW(e_opt_serial, E_OPTIONS_BUFF_MAX_LEN, E_OPTIONS_BUFF_MAX_LEN);

	/* Convert all E-options structure to byte string, and copy it to 
	output*/
	TRY(options_serialize(E_options, E_options_cnt, &e_opt_serial));

	uint32_t dest_size = (plaintext->len - (uint32_t)(temp_plaintext_ptr +
							  1 - plaintext->ptr));
	TRY(_memcpy_s(++temp_plaintext_ptr, dest_size, e_opt_serial.ptr,
		      e_opt_serial.len));
	temp_plaintext_ptr += e_opt_serial.len;

	/* Add payload to plaintext*/
	if (in_o_coap->payload.len != 0) {
		/* An extra byte 0xFF before payload*/
		*temp_plaintext_ptr = 0xff;

		dest_size = (plaintext->len - (uint32_t)(temp_plaintext_ptr +
							 1 - plaintext->ptr));
		TRY(_memcpy_s(++temp_plaintext_ptr, dest_size,
			      in_o_coap->payload.ptr, in_o_coap->payload.len));
	}
	PRINT_ARRAY("Plain text", plaintext->ptr, plaintext->len);
	return ok;
}

/**
 * @brief   OSCORE option value length
 * @param   piv_len length of the PIV array
 * @param   kid_len length of the KID array
 * @param   kid_context_len length of the KID context array
 * @return  length of the OSCORE option value
 */
static inline uint32_t get_oscore_opt_val_len(uint32_t piv_len,
					      uint32_t kid_len,
					      uint32_t kid_context_len)
{
	uint32_t length = piv_len + kid_len + kid_context_len;
	if (length) {
		/*if any of piv, kid_context or kid is present 1 byte for the flags is reserved */
		length++;
	}
	if (kid_context_len) {
		/*if kid_context is present one byte is reserved for the s field*/
		length++;
	}
	return length;
}

/**
 * @brief   Generate an OSCORE option.
 * @param   piv set to the trimmed sender sequence number in requests or NULL 
 *          in responses
 * @param   kid set to Sender ID in requests or NULL in responses
 * @param   kid_context set to ID context in request when present. If not 
 *          present or a response set to NULL
 * @param   oscore_option: output pointer OSCORE option structure
 * @return  err
 */
STATIC enum err oscore_option_generate(struct byte_array *piv,
				       struct byte_array *kid,
				       struct byte_array *kid_context,
				       struct oscore_option *oscore_option)
{
	uint32_t piv_len = (NULL == piv) ? 0 : piv->len;
	uint32_t kid_len = (NULL == kid) ? 0 : kid->len;
	uint32_t kid_context_len = (NULL == kid_context) ? 0 : kid_context->len;

	oscore_option->option_number = OSCORE;
	oscore_option->len = (uint8_t)get_oscore_opt_val_len(piv_len, kid_len,
							     kid_context_len);
	TRY(check_buffer_size(OSCORE_OPT_VALUE_LEN, oscore_option->len));
	oscore_option->value = oscore_option->buf;

	uint32_t dest_size;

	if (oscore_option->len == 0) {
		oscore_option->value = NULL;
	} else {
		memset(oscore_option->value, 0, oscore_option->len);

		uint8_t *temp_ptr = oscore_option->value;

		if (piv_len != 0) {
			/* Set header bits of PIV */
			oscore_option->value[0] =
				(uint8_t)(oscore_option->value[0] | piv->len);
			/* copy PIV (sender sequence) */

			dest_size = (uint32_t)(
				oscore_option->len -
				(temp_ptr + 1 - oscore_option->value));
			TRY(_memcpy_s(++temp_ptr, dest_size, piv->ptr,
				      piv->len));

			temp_ptr += piv->len;
		} else {
			temp_ptr++;
		}

		if (kid_context_len != 0) {
			/* Set header flag bit of KID context */
			oscore_option->value[0] |= COMP_OSCORE_OPT_KIDC_H_MASK;
			/* Copy length and context value */
			*temp_ptr = (uint8_t)(kid_context->len);

			dest_size = (uint32_t)(
				oscore_option->len -
				(temp_ptr + 1 - oscore_option->value));
			TRY(_memcpy_s(++temp_ptr, dest_size, kid_context->ptr,
				      kid_context->len));

			temp_ptr += kid_context->len;
		}

		/* Set header flag bit of KID */
		/* The KID header flag is set always in requests */
		/* This function is not called in responses */
		oscore_option->value[0] |= COMP_OSCORE_OPT_KID_K_MASK;
		if (kid_len != 0) {
			/* Copy KID */
			dest_size =
				(uint32_t)(oscore_option->len -
					   (temp_ptr - oscore_option->value));
			TRY(_memcpy_s(temp_ptr, dest_size, kid->ptr, kid->len));
		}
	}

	PRINT_ARRAY("OSCORE option value", oscore_option->value,
		    oscore_option->len);
	return ok;
}

/**
 * @brief Generate an OSCORE packet with all needed data
 * @param in_o_coap: input CoAP packet
 * @param out_oscore: output pointer to OSCORE packet
 * @param U_options: pointer to array of all unprotected options, including OSCORE_option
 * @param U_options_cnt: count number of U-options
 * @param in_ciphertext: input ciphertext, will be set into payload in OSCORE packet
 * @param oscore_option: The OSCORE option
 * @return err
 *
 */
STATIC enum err oscore_pkg_generate(struct o_coap_packet *in_o_coap,
				    struct o_coap_packet *out_oscore,
				    struct o_coap_option *u_options,
				    uint8_t u_options_cnt,
				    struct byte_array *in_ciphertext,
				    struct oscore_option *oscore_option)
{
	/* Set OSCORE header and Token*/
	out_oscore->header.ver = in_o_coap->header.ver;
	out_oscore->header.type = in_o_coap->header.type;
	out_oscore->header.TKL = in_o_coap->header.TKL;
	out_oscore->header.MID = in_o_coap->header.MID;
	if (out_oscore->header.TKL == 0) {
		out_oscore->token = NULL;
	} else {
		out_oscore->token = in_o_coap->token;
	}

	bool observe = is_observe(u_options, u_options_cnt);
	if (is_request(in_o_coap)) {
		if (observe) {
			out_oscore->header.code = CODE_REQ_FETCH;
		} else {
			out_oscore->header.code = CODE_REQ_POST;
		}
	} else {
		if (observe) {
			out_oscore->header.code = CODE_RESP_CONTENT;
		} else {
			out_oscore->header.code = CODE_RESP_CHANGED;
		}
	}

	/* U-options + OSCORE option (compare oscore option number with others)
	 Find out the appropriate position of OSCORE option */
	uint8_t oscore_opt_pos = u_options_cnt;
	for (uint8_t i = 0; i < u_options_cnt; i++) {
		/* Once found, finish the for-loop */
		if (u_options[i].option_number > OSCORE) {
			oscore_opt_pos = i;
			break;
		}
	}

	/* Update options count number to output*/
	out_oscore->options_cnt = (uint8_t)(1 + u_options_cnt);

	uint8_t temp_opt_number_sum = 0;
	/* Show the position of U-options */
	uint8_t u_opt_pos = 0;
	for (uint8_t i = 0; i < u_options_cnt + 1; i++) {
		if (i == oscore_opt_pos) {
			/* OSCORE_option */
			out_oscore->options[i].delta =
				(uint16_t)(oscore_option->option_number -
					   temp_opt_number_sum);
			out_oscore->options[i].len = oscore_option->len;
			out_oscore->options[i].option_number =
				oscore_option->option_number;
			out_oscore->options[i].value = oscore_option->value;
		} else {
			/* U-options */
			out_oscore->options[i].delta =
				(uint16_t)(u_options[u_opt_pos].option_number -
					   temp_opt_number_sum);
			out_oscore->options[i].len = u_options[u_opt_pos].len;
			out_oscore->options[i].option_number =
				u_options[u_opt_pos].option_number;
			out_oscore->options[i].value =
				u_options[u_opt_pos].value;

			u_opt_pos++;
		}
		temp_opt_number_sum = (uint8_t)(temp_opt_number_sum +
						out_oscore->options[i].delta);
	}

	/* Protected Payload */
	out_oscore->payload.len = in_ciphertext->len;
	out_oscore->payload.ptr = in_ciphertext->ptr;
	return ok;
}

/**
 * @brief Increment Sender Sequence Number and call the function to periodically write it to NVM.
 * 
 * @param c Security context.
 * @return enum err 
 */
static enum err generate_new_ssn(struct context *c)
{
	if (NULL == c) {
		return wrong_parameter;
	}

	c->sc.ssn++;

#ifdef OSCORE_NVM_SUPPORT
	struct nvm_key_t nvm_key = { .sender_id = c->sc.sender_id,
				     .recipient_id = c->rc.recipient_id,
				     .id_context = c->cc.id_context };
	bool echo_sync_in_progress =
		(ECHO_SYNCHRONIZED != c->rrc.echo_state_machine);
	return ssn_store_in_nvm(&nvm_key, c->sc.ssn, echo_sync_in_progress);
#else
	return ok;
#endif
}

/**
 * @brief Checks if given message needs a fresh PIV/nonce, based on its type and current state of ECHO challenge.
 * @param msg_type Message type.
 * @param echo_state ECHO challenge state.
 * @return If true, new PIV/nonce must be generated.
 */
static bool needs_new_piv(enum o_coap_msg msg_type, enum echo_state echo_state)
{
	/* Encrypt data using new PIV/nonce in the following cases:
		- Client prepares any kind of request.
		- Server prepares a response with ECHO challenge after the reboot (see RFC 8613 Appendix B.1.2).
		- Server prepares a notification (response) to an observe registration.
	   Encrypt data using corresponding request nonce:
		- Server prepares a response to a request after the ECHO challenge.
	   For more details, see RFC 8613 p. 8.3 and the following hyperlinks.*/
	return ((COAP_MSG_RESPONSE != msg_type) || (ECHO_VERIFY == echo_state));
}

/**
 * @brief Wrapper function with common operations for encrypting the payload.
 *        These operations are shared in all possible scenarios.
 *        For more info, see RFC8616 8.1 and 8.3.
 * 
 * @param plaintext Input plaintext to be encrypted.
 * @param ciphertext Output encrypted payload for the OSCORE packet.
 * @param c Security context.
 * @param input_coap Input coap packet.
 * @param oscore_option Output OSCORE option.
 * @return enum err 
 */
static enum err encrypt_wrapper(struct byte_array *plaintext,
				struct byte_array *ciphertext,
				struct context *c,
				struct o_coap_packet *input_coap,
				struct oscore_option *oscore_option)
{
	BYTE_ARRAY_NEW(new_piv, MAX_PIV_LEN, MAX_PIV_LEN);
	BYTE_ARRAY_NEW(new_nonce, NONCE_LEN, NONCE_LEN);
	struct byte_array piv = BYTE_ARRAY_INIT(NULL, 0);
	struct byte_array kid = BYTE_ARRAY_INIT(NULL, 0);
	struct byte_array kid_context = BYTE_ARRAY_INIT(NULL, 0);
	struct byte_array nonce;

	/* Read necessary fields from the input packet. */
	enum o_coap_msg msg_type;
	TRY(coap_get_message_type(input_coap, &msg_type));
	struct byte_array token =
		BYTE_ARRAY_INIT(input_coap->token, input_coap->header.TKL);

	/* Generate new PIV/nonce if needed. */
	bool use_new_piv = needs_new_piv(msg_type, c->rrc.echo_state_machine);
	if (use_new_piv) {
		TRY(ssn2piv(c->sc.ssn, &new_piv));
		TRY(generate_new_ssn(c));
		TRY(create_nonce(&c->sc.sender_id, &new_piv, &c->cc.common_iv,
				 &new_nonce));

		nonce = new_nonce;
		piv = new_piv;
		kid = c->sc.sender_id;
		kid_context = c->cc.id_context;
	} else {
		nonce = c->rrc.nonce;
	}

	/* Generate OSCORE option based on selected values. */
	TRY(oscore_option_generate(&piv, &kid, &kid_context, oscore_option));

	/* AAD shares the same format for both requests and responses, 
	   yet request_kid and request_piv fields are only used by responses.
	   For more details, see 5.4. */
	BYTE_ARRAY_NEW(aad, MAX_AAD_LEN, MAX_AAD_LEN);
	struct byte_array request_piv = piv;
	struct byte_array request_kid = kid;
	TRY(oscore_interactions_read_wrapper(msg_type, &token,
					     c->rrc.interactions, &request_piv,
					     &request_kid));
	TRY(create_aad(NULL, 0, c->cc.aead_alg, &request_kid, &request_piv,
		       &aad));

	/* Encrypt the plaintext */
	TRY(oscore_cose_encrypt(plaintext, ciphertext, &nonce, &aad,
				&c->sc.sender_key));

	/* Update nonce only after successful encryption (for handling future responses). */
	if (use_new_piv) {
		TRY(byte_array_cpy(&c->rrc.nonce, &nonce, NONCE_LEN));
	}

	/* Handle OSCORE interactions after successful encryption. */
	BYTE_ARRAY_NEW(uri_paths, OSCORE_MAX_URI_PATH_LEN,
		       OSCORE_MAX_URI_PATH_LEN);
	TRY(uri_path_create(input_coap->options, input_coap->options_cnt,
			    uri_paths.ptr, &(uri_paths.len)));
	TRY(oscore_interactions_update_wrapper(msg_type, &token, &uri_paths,
					       c->rrc.interactions,
					       &request_piv, &request_kid));

	return ok;
}

/**
 *@brief 	Converts a CoAP packet to OSCORE packet
 *@note		For messaging layer packets (simple ACK with no payload, code 0.00),
 *			encryption is dismissed and raw input buffer is copied, 
 *			as specified at section 4.2 in RFC8613.
 *@param	buf_o_coap a buffer containing a CoAP packet
 *@param	buf_o_coap_len length of the CoAP buffer
 *@param	buf_oscore a buffer where the OSCORE packet will be written
 *@param	buf_oscore_len length of the OSCORE packet
 *@param	c a struct containing the OSCORE context
 *
 *@return	err
 */
enum err coap2oscore(uint8_t *buf_o_coap, uint32_t buf_o_coap_len,
		     uint8_t *buf_oscore, uint32_t *buf_oscore_len,
		     struct context *c)
{
	struct o_coap_packet o_coap_pkt;
	struct byte_array buf;
	uint32_t plaintext_len = 0;

	PRINT_MSG("\n\n\ncoap2oscore***************************************\n");
	PRINT_ARRAY("Input CoAP packet", buf_o_coap, buf_o_coap_len);

	buf.len = buf_o_coap_len;
	buf.ptr = buf_o_coap;

	/* Make sure that given context is fresh enough to process the message. */
	TRY(check_context_freshness(c));

	/* Parse the coap buf into a CoAP struct */
	memset(&o_coap_pkt, 0, sizeof(o_coap_pkt));
	TRY(coap_deserialize(&buf, &o_coap_pkt));

	/* Dismiss OSCORE encryption if messaging layer detected (simple ACK, code=0.00) */
	if ((TYPE_ACK == o_coap_pkt.header.type) &&
	    (CODE_EMPTY == o_coap_pkt.header.code)) {
		PRINT_MSG(
			"Messaging Layer CoAP packet detected, encryption dismissed\n");
		*buf_oscore_len = buf_o_coap_len;
		return _memcpy_s(buf_oscore, buf_o_coap_len, buf_o_coap,
				 buf_o_coap_len);
	}

	/* 1. Divide CoAP options into E-option and U-option */
	struct o_coap_option e_options[MAX_OPTION_COUNT];
	uint8_t e_options_cnt = 0;
	uint16_t e_options_len = 0;
	struct o_coap_option u_options[MAX_OPTION_COUNT];
	uint8_t u_options_cnt = 0;

	/* Analyze CoAP options, extract E-options and U-options */
	TRY(inner_outer_option_split(&o_coap_pkt, e_options, &e_options_cnt,
				     &e_options_len, u_options,
				     &u_options_cnt));

	/* 2. Create plaintext (code + E-options + o_coap_payload) */
	/* Calculate complete plaintext length: 1 byte code + E-options + 1 byte 0xFF + payload */
	plaintext_len = (uint32_t)(1 + e_options_len);

	if (o_coap_pkt.payload.len) {
		plaintext_len = plaintext_len + 1 + o_coap_pkt.payload.len;
	}

	/* Setup buffer for plaintext */
	BYTE_ARRAY_NEW(plaintext, MAX_PLAINTEXT_LEN, plaintext_len);

	/* Combine code, E-options and payload of CoAP to plaintext */
	TRY(plaintext_setup(&o_coap_pkt, e_options, e_options_cnt, &plaintext));

	/* Generate ciphertext array */
	BYTE_ARRAY_NEW(ciphertext, MAX_CIPHERTEXT_LEN,
		       plaintext.len + AUTH_TAG_LEN);

	if (ECHO_VERIFY == c->rrc.echo_state_machine) {
		/* A server prepares a response with ECHO challenge after the reboot. */
		TRY(cache_echo_val(&c->rrc.echo_opt_val, e_options,
				   e_options_cnt));
	}

	/* Encrypt data using either a freshly generated nonce (if needed), or the one cached from the corresponding request. */
	struct oscore_option oscore_option;
	TRY(encrypt_wrapper(&plaintext, &ciphertext, c, &o_coap_pkt,
			    &oscore_option));

	/*create an OSCORE packet*/
	struct o_coap_packet oscore_pkt;
	TRY(oscore_pkg_generate(&o_coap_pkt, &oscore_pkt, u_options,
				u_options_cnt, &ciphertext, &oscore_option));

	/*convert the oscore pkg to byte string*/
	return coap_serialize(&oscore_pkt, buf_oscore, buf_oscore_len);
}
