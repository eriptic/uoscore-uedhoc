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
#include "oscore/replay_protection.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

/**
 * @brief 	Parse all received options to find the OSCORE option. If it doesn't  
 * 		 	have OSCORE option, then this packet is a normal CoAP. If it does 
 * 			have, it's an OSCORE packet, and then parse the compressed OSCORE 
 * 			option value to get value of PIV, KID and KID context of the client.
 * @param in: input OSCORE packet
 * @param out: pointer output compressed OSCORE_option
 * @return error code
 */
static inline enum err
oscore_option_parser(struct o_coap_packet *in,
		     struct compressed_oscore_option *out)
{
	uint8_t temp_option_count = in->options_cnt;
	struct o_coap_option *temp_options = in->options;
	uint8_t temp_option_num = 0;
	uint8_t *temp_current_option_value_ptr;
	uint8_t temp_kid_len = 0;

	enum err r = not_oscore_pkt;

	for (uint8_t i = 0; i < temp_option_count; i++) {
		temp_option_num = temp_options[i].option_number;
		temp_kid_len = temp_options[i].len;

		/* Check current option is OSCORE_option or not */
		if (temp_option_num == OSCORE) {
			if (temp_options[i].len == 0) {
				/* No OSCORE option value*/
				out->h = 0;
				out->k = 0;
				out->n = 0;
				out->piv.ptr = NULL;
				out->piv.len = 0;
				out->kid.ptr = NULL;
				out->kid.len = 0;
				out->kid_context.ptr = NULL;
				out->kid_context.len = 0;
			} else {
				/* Get address of current option value*/
				temp_current_option_value_ptr =
					temp_options[i].value;
				/* Parse first byte of OSCORE value*/
				out->h = ((*temp_current_option_value_ptr) &
					  COMP_OSCORE_OPT_KIDC_H_MASK) >>
					 COMP_OSCORE_OPT_KIDC_H_OFFSET;
				out->k = ((*temp_current_option_value_ptr) &
					  COMP_OSCORE_OPT_KID_K_MASK) >>
					 COMP_OSCORE_OPT_KID_K_OFFSET;
				out->n = ((*temp_current_option_value_ptr) &
					  COMP_OSCORE_OPT_PIV_N_MASK) >>
					 COMP_OSCORE_OPT_PIV_N_OFFSET;
				temp_current_option_value_ptr++;
				temp_kid_len--;

				/* Get PIV */
				switch (out->n) {
				case 0:
					/* NO PIV in COSE object*/
					out->piv.ptr = NULL;
					break;
				case 6:
				case 7:
					/* ERROR: Byte length of PIV not right, max. 5 bytes */
					return oscore_inpkt_invalid_piv;
					break;
				default:
					out->piv.ptr =
						temp_current_option_value_ptr;
					out->piv.len = out->n;
					temp_current_option_value_ptr += out->n;
					temp_kid_len = (uint8_t)(temp_kid_len -
								 out->n);
					break;
				}

				/* Get KID context */
				if (out->h == 0) {
					out->kid_context.len = 0;
					out->kid_context.ptr = NULL;
				} else {
					out->kid_context.len =
						*temp_current_option_value_ptr;
					out->kid_context.ptr =
						++temp_current_option_value_ptr;
					temp_current_option_value_ptr +=
						out->kid_context.len;
					temp_kid_len =
						(uint8_t)(temp_kid_len -
							  (out->kid_context.len +
							   1));
				}

				/* Get KID */
				if (out->k == 0) {
					out->kid.len = 0;
					out->kid.ptr = NULL;
				} else {
					out->kid.len = temp_kid_len;
					out->kid.ptr =
						temp_current_option_value_ptr;
				}
			}

			r = ok;
		}
	}

	return r;
}

/**
 * @brief 	Decrypt the OSCORE payload (ciphertext)
 * @param 	c pointer to a security context
 * @param out_plaintext: output plaintext
 * @param oscore_packet: complete OSCORE packet which contains the ciphertext to be decrypted
 * @return void
 */
static inline enum err payload_decrypt(struct context *c,
				       struct byte_array *aad,
				       struct byte_array *out_plaintext,
				       struct o_coap_packet *oscore_packet)
{
	struct byte_array oscore_ciphertext = {
		.len = oscore_packet->payload_len,
		.ptr = oscore_packet->payload,
	};
	return oscore_cose_decrypt(&oscore_ciphertext, out_plaintext,
				   &c->rrc.nonce, aad, &c->rc.recipient_key);
}

/**
 * @brief Reorder E-options and other U-options, and update their delta, and combine them all to normal CoAP packet
 * @param oscore_pkt: input OSCORE, which contains U-options
 * @param E_options: input pointer to E-options array
 * @param E_options_cnt: count number of input E-options
 * @param out: output pointer to CoAP packet, which will have all reordered options
 * @return ok or error code
 */
static inline enum err
options_from_oscore_reorder(struct o_coap_packet *oscore_pkt,
			    struct o_coap_option *E_options,
			    uint8_t E_options_cnt, struct o_coap_packet *out)
{
	// uint16_t temp_delta_sum = 0;

	/*the maximum amount of options for the CoAP packet 
	is the amount of all options -1 (for the OSCORE option)*/
	uint8_t max_coap_opt_cnt =
		(uint8_t)(oscore_pkt->options_cnt + E_options_cnt - 1);

	TRY(check_buffer_size(out->options_cnt, max_coap_opt_cnt));
	out->options_cnt = 0;

	/*Get the all outer options. Discard OSCORE and outer OBSERVE */
	for (uint8_t i = 0; i < oscore_pkt->options_cnt; i++) {
		if ((oscore_pkt->options[i].option_number != OSCORE) &&
		    (oscore_pkt->options[i].option_number != OBSERVE)) {
			out->options[out->options_cnt++] =
				oscore_pkt->options[i];
		}
	}

	/*Get the inner options.*/
	for (uint8_t i = 0; i < E_options_cnt; i++) {
		out->options[out->options_cnt++] = E_options[i];
	}

	uint16_t delta = 0;
	/* Order the options starting with minimum option number to maximum */
	for (uint8_t i = 0; i < out->options_cnt; i++) {
		uint8_t ipp = (uint8_t)(i + 1);
		for (uint8_t k = ipp; k < out->options_cnt; k++) {
			if (out->options[i].option_number >
			    out->options[k].option_number) {
				struct o_coap_option tmp;
				tmp = out->options[i];
				out->options[i] = out->options[k];
				out->options[k] = tmp;
			}
		}
		/*update the delta*/
		out->options[i].delta = out->options[i].option_number - delta;
		delta = out->options[i].option_number;
	}

	return ok;
}

/**
 * @brief Generate CoAP packet from OSCORE packet
 * @param decrypted_payload: decrypted OSCORE payload, which contains code, E-options and original unprotected CoAP payload
 * @param oscore_pkt:  input OSCORE packet
 * @param out: pointer to output CoAP packet
 * @return
 */
static inline enum err o_coap_pkg_generate(struct byte_array *decrypted_payload,
					   struct o_coap_packet *oscore_pkt,
					   struct o_coap_packet *out)
{
	uint8_t code = 0;
	struct byte_array unprotected_o_coap_payload = {
		.len = 0,
		.ptr = NULL,
	};
	struct o_coap_option E_options[10];
	uint8_t E_options_cnt = 0;

	/* Parse decrypted payload: code + options + unprotected CoAP payload*/
	TRY(oscore_decrypted_payload_parser(decrypted_payload, &code, E_options,
					    &E_options_cnt,
					    &unprotected_o_coap_payload));

	/* Copy each items from OSCORE packet to CoAP packet */
	/* Header */
	out->header.ver = oscore_pkt->header.ver;
	out->header.type = oscore_pkt->header.type;
	out->header.TKL = oscore_pkt->header.TKL;
	out->header.code = code;
	out->header.MID = oscore_pkt->header.MID;

	/* Token */
	if (oscore_pkt->header.TKL == 0)
		out->token = NULL;
	else
		out->token = oscore_pkt->token;

	/* Payload */
	out->payload_len = unprotected_o_coap_payload.len;
	if (unprotected_o_coap_payload.len == 0)
		out->payload = NULL;
	else
		out->payload = unprotected_o_coap_payload.ptr;

	out->options_cnt = sizeof(out->options);
	/* reorder all options, and copy it to output coap packet */
	TRY(options_from_oscore_reorder(oscore_pkt, E_options, E_options_cnt,
					out));
	return ok;
}

enum err oscore2coap(uint8_t *buf_in, uint32_t buf_in_len, uint8_t *buf_out,
		     uint32_t *buf_out_len, struct context *c)
{
	struct o_coap_packet oscore_packet;
	struct compressed_oscore_option oscore_option;
	struct byte_array buf;

	PRINT_MSG("\n\n\noscore2coap***************************************\n");
	PRINT_ARRAY("Input OSCORE packet", buf_in, buf_in_len);

	buf.ptr = buf_in;
	buf.len = buf_in_len;

	/*Parse the incoming message (buf_in) into a CoAP struct*/
	memset(&oscore_packet, 0, sizeof(oscore_packet));
	TRY(buf2coap(&buf, &oscore_packet));

	/* Check if the packet is OSCORE packet and if so parse the OSCORE option */
	TRY(oscore_option_parser(&oscore_packet, &oscore_option));

	/* Setup buffer for the plaintext. The plaintext is shorter than the 
	ciphertext because of the authentication tag*/
	uint32_t plaintext_bytes_len = oscore_packet.payload_len - AUTH_TAG_LEN;
	BYTE_ARRAY_NEW(plaintext, MAX_PLAINTEXT_LEN, plaintext_bytes_len);

	/*In requests the OSCORE packet contains at least a KID = sender ID 
        and eventually sender sequence number*/
	if (is_request(&oscore_packet)) {
		/*Check that the recipient context c->rc has a  Recipient ID that
			 matches the received with the oscore option KID (Sender ID).
			 If this is not true return an error which indicates the caller
			 application to tray another context. This is useful when the caller
			 app doesn't know in advance to which context an incoming packet 
             belongs.*/
		if (!array_equals(&c->rc.recipient_id, &oscore_option.kid)) {
			return oscore_kid_recipient_id_mismatch;
		}

		TRY(update_request_piv_request_kid(c, &oscore_option.piv,
						   &oscore_option.kid, true));

		/*first request after reboot*/
		if (c->rrc.reboot) {
			c->rrc.reboot = false;
			c->rrc.second_req_expected = true;
			PRINT_MSG("Abort -- first request after reboot!\n");
			return first_request_after_reboot;
		}

		/*check if the packet is replayed*/
		if (!c->rrc.second_req_expected) {
			PRINT_MSG("Is the message replied?\n");
			if (!server_is_sequence_number_valid(
				    *oscore_option.piv.ptr,
				    &c->rc.replay_window)) {
				PRINT_MSG("Yes, the message is replied!\n");
				return oscore_replay_window_protection_error;
			}
			PRINT_MSG("No, the message is not replied!\n");
		}

		/*calculate nonce*/
		TRY(create_nonce(&oscore_option.kid, &oscore_option.piv,
				 &c->cc.common_iv, &c->rrc.nonce));

		/*compute AAD*/
		uint8_t aad_buf[MAX_AAD_LEN];
		struct byte_array aad =
			BYTE_ARRAY_INIT(aad_buf, sizeof(aad_buf));
		TRY(create_aad(NULL, 0, c->cc.aead_alg, &c->rrc.request_kid,
			       &c->rrc.request_piv, &aad));

		/* Decrypt payload */
		TRY(payload_decrypt(c, &aad, &plaintext, &oscore_packet));

		if (c->rrc.second_req_expected) {
			/*if this is a second request after reboot it should have an ECHO option for proving freshness*/
			TRY(echo_val_is_fresh(&c->rrc.echo_opt_val,
					      &plaintext));
			/*reinitialize replay window*/
			TRY(server_replay_window_reinit(*oscore_option.piv.ptr,
							&c->rc.replay_window));
			c->rrc.second_req_expected = false;
		} else {
			server_replay_window_update(*oscore_option.piv.ptr,
						    &c->rc.replay_window);
		}
	} else {
		TRY(verify_token(&c->rrc.token_request,
				 oscore_packet.header.TKL,
				 oscore_packet.token));

		if (oscore_option.piv.len != 0) {
			if (is_observe(oscore_packet.options,
				       oscore_packet.options_cnt)) {
				PRINT_MSG(
					"Observe notification with PIV received\n");

				TRY(replay_protection_check_notification(
					c->rc.notification_num,
					c->rc.notification_num_initialized,
					&oscore_option.piv));

				TRY(create_nonce(
					&oscore_option.kid, &oscore_option.piv,
					&c->cc.common_iv, &c->rrc.nonce));

				/*compute AAD*/
				uint8_t aad_buf[MAX_AAD_LEN];
				struct byte_array aad = BYTE_ARRAY_INIT(
					aad_buf, sizeof(aad_buf));
				TRY(create_aad(NULL, 0, c->cc.aead_alg,
					       &c->rrc.request_kid,
					       &c->rrc.request_piv, &aad));

				/* Decrypt payload */
				TRY(payload_decrypt(c, &aad, &plaintext,
						    &oscore_packet));

				/*update replay protection value in context*/
				TRY(notification_number_update(
					&c->rc.notification_num,
					&c->rc.notification_num_initialized,
					&oscore_option.piv));
			} else {
				TRY(create_nonce(
					&oscore_option.kid, &oscore_option.piv,
					&c->cc.common_iv, &c->rrc.nonce));

				/*compute AAD*/
				uint8_t aad_buf[MAX_AAD_LEN];
				struct byte_array aad = BYTE_ARRAY_INIT(
					aad_buf, sizeof(aad_buf));
				TRY(create_aad(NULL, 0, c->cc.aead_alg,
					       &c->rrc.request_kid,
					       &c->rrc.request_piv, &aad));

				/* Decrypt payload */
				TRY(payload_decrypt(c, &aad, &plaintext,
						    &oscore_packet));
			}
		} else {
			/*compute AAD*/
			uint8_t aad_buf[MAX_AAD_LEN];
			struct byte_array aad =
				BYTE_ARRAY_INIT(aad_buf, sizeof(aad_buf));
			TRY(create_aad(NULL, 0, c->cc.aead_alg,
				       &c->rrc.request_kid, &c->rrc.request_piv,
				       &aad));

			/* Decrypt payload */
			TRY(payload_decrypt(c, &aad, &plaintext,
					    &oscore_packet));
		}
	}

	/* Generate corresponding CoAP packet */
	struct o_coap_packet o_coap_packet;
	TRY(o_coap_pkg_generate(&plaintext, &oscore_packet, &o_coap_packet));

	/*Convert to byte string*/
	return coap2buf(&o_coap_packet, buf_out, buf_out_len);
}
