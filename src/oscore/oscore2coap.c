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
#include "common/unit_test.h"

/**
 * @brief 	Parse all received options to find the OSCORE option. If it doesn't  
 * 		 	have OSCORE option, then this packet is a normal CoAP. If it does 
 * 			have, it's an OSCORE packet, and then parse the compressed OSCORE 
 * 			option value to get value of PIV, KID and KID context of the client.
 * @param opt: input array of options
 * @param opt_cnt: number of elements in the array
 * @param out: pointer output compressed OSCORE_option
 * @return error code
 */
STATIC enum err oscore_option_parser(const struct o_coap_option *opt,
				     uint8_t opt_cnt,
				     struct compressed_oscore_option *out)
{
	uint8_t *val_ptr;
	uint16_t temp_kid_len = 0;

	enum err r = not_oscore_pkt;

	for (uint8_t i = 0; i < opt_cnt; i++) {
		temp_kid_len = opt[i].len;

		/* Check current option is OSCORE_option or not */
		if (opt[i].option_number == OSCORE) {
			if (opt[i].len == 0) {
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
				val_ptr = opt[i].value;
				/* Parse first byte of OSCORE value*/
				out->h = ((*val_ptr) &
					  COMP_OSCORE_OPT_KIDC_H_MASK) >>
					 COMP_OSCORE_OPT_KIDC_H_OFFSET;
				out->k = ((*val_ptr) &
					  COMP_OSCORE_OPT_KID_K_MASK) >>
					 COMP_OSCORE_OPT_KID_K_OFFSET;
				out->n = ((*val_ptr) &
					  COMP_OSCORE_OPT_PIV_N_MASK) >>
					 COMP_OSCORE_OPT_PIV_N_OFFSET;
				val_ptr++;
				temp_kid_len--;

				/* Get PIV */
				switch (out->n) {
				case 0:
					/* NO PIV in COSE object*/
					out->piv.ptr = NULL;
					out->piv.len = 0;
					break;
				case 6:
				case 7:
					/* ERROR: Byte length of PIV not right, max. 5 bytes */
					return oscore_inpkt_invalid_piv;
					break;
				default:
					out->piv.ptr = val_ptr;
					out->piv.len = out->n;
					val_ptr += out->n;
					temp_kid_len = (uint8_t)(temp_kid_len -
								 out->n);
					break;
				}

				/* Get KID context */
				if (out->h == 0) {
					out->kid_context.len = 0;
					out->kid_context.ptr = NULL;
				} else {
					out->kid_context.len = *val_ptr;
					out->kid_context.ptr = ++val_ptr;
					val_ptr += out->kid_context.len;
					temp_kid_len = (uint8_t)(
						temp_kid_len -
						(out->kid_context.len + 1));
				}

				/* Get KID */
				if (out->k == 0) {
					out->kid.len = 0;
					out->kid.ptr = NULL;
				} else {
					out->kid.len = temp_kid_len;
					out->kid.ptr = val_ptr;
				}
			}

			r = ok;
		}
	}

	return r;
}

/**
 * @brief Reorder E-options and other U-options, and update their delta, and combine them all to normal CoAP packet
 * @param oscore_pkt: input OSCORE, which contains U-options
 * @param E_options: input pointer to E-options array
 * @param E_options_cnt: count number of input E-options
 * @param out: output pointer to CoAP packet, which will have all reordered options
 * @return ok or error code
 */

STATIC enum err
options_reorder(struct o_coap_option *U_options, uint8_t U_options_cnt,
		struct o_coap_option *E_options, uint8_t E_options_cnt,
		struct o_coap_option *out_options, uint8_t *out_options_cnt)
{
	/*the maximum amount of options for the CoAP packet 
	is the amount of all options -1 (for the OSCORE option)*/
	uint8_t max_coap_opt_cnt = (uint8_t)(U_options_cnt + E_options_cnt - 1);

	TRY(check_buffer_size(MAX_OPTION_COUNT, max_coap_opt_cnt));
	*out_options_cnt = 0;
	memset(out_options, 0, sizeof(struct o_coap_option) * max_coap_opt_cnt);

	/*Get the all outer options. Discard OSCORE and outer OBSERVE as specified in 8.2 and 8.4 */
	for (uint8_t i = 0; i < U_options_cnt; i++) {
		if ((U_options[i].option_number != OSCORE) &&
		    (U_options[i].option_number != OBSERVE)) {
			out_options[*out_options_cnt] = U_options[i];
			*out_options_cnt += 1;
		}
	}

	/*Get the inner options.*/
	for (uint8_t i = 0; i < E_options_cnt; i++) {
		out_options[*out_options_cnt] = E_options[i];
		*out_options_cnt += 1;
	}

	uint16_t delta = 0;
	/* Order the options starting with minimum option number to maximum */
	for (uint8_t i = 0; i < *out_options_cnt; i++) {
		uint8_t ipp = (uint8_t)(i + 1);
		for (uint8_t k = ipp; k < *out_options_cnt; k++) {
			if (out_options[i].option_number >
			    out_options[k].option_number) {
				struct o_coap_option tmp;
				tmp = out_options[i];
				out_options[i] = out_options[k];
				out_options[k] = tmp;
			}
		}
		/*update the delta*/
		out_options[i].delta = out_options[i].option_number - delta;
		delta = out_options[i].option_number;
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
	struct byte_array unprotected_o_coap_payload = BYTE_ARRAY_INIT(NULL, 0);
	struct o_coap_option E_options[MAX_E_OPTION_COUNT];
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
	out->token = oscore_pkt->token;
	out->header.code = code; //decrypted code must be used, see 8.2 p.7
	out->header.MID = oscore_pkt->header.MID;

	/* Payload */
	out->payload.len = unprotected_o_coap_payload.len;
	if (unprotected_o_coap_payload.len == 0) {
		out->payload.ptr = NULL;
	} else {
		out->payload.ptr = unprotected_o_coap_payload.ptr;
	}

	/* reorder all options, and copy it to output coap packet */
	TRY(options_reorder(oscore_pkt->options, oscore_pkt->options_cnt,
			    E_options, E_options_cnt, out->options,
			    &out->options_cnt));
	return ok;
}

/**
 * @brief Wrapper function with common operations for decrypting the payload.
 *        These operations are shared in all possible scenarios.
 *        For more info, see RFC8616 8.2 and 8.4.
 * 
 * @param ciphertext Input encrypted payload.
 * @param plaintext Output decrypted payload.
 * @param c Security context.
 * @param new_nonce_oscore_option Input OSCORE option from the packet.
 *        Use proper pointer for cases when new nonce are generated, or
 *        NULL if data from corresponding request should be used.
 * @param input_oscore Input OSCORE packet.
 * @param output_coap Output decrypted coap packet.
 * @return enum err 
 */
static enum err
decrypt_wrapper(struct byte_array *ciphertext, struct byte_array *plaintext,
		struct context *c,
		struct compressed_oscore_option *new_nonce_oscore_option,
		struct o_coap_packet *input_oscore,
		struct o_coap_packet *output_coap)
{
	BYTE_ARRAY_NEW(new_nonce, NONCE_LEN, NONCE_LEN);
	struct byte_array nonce;

	/* Read necessary fields from the input packet. */
	enum o_coap_msg msg_type_oscore;
	TRY(coap_get_message_type(input_oscore, &msg_type_oscore));
	struct byte_array token =
		BYTE_ARRAY_INIT(input_oscore->token, input_oscore->header.TKL);

	/* Read Request PIV and KID fields from OSCORE option, if available. Update using interactions wrapper. */
	struct byte_array request_piv;
	struct byte_array request_kid;
	if (NULL != new_nonce_oscore_option) {
		request_piv = new_nonce_oscore_option->piv;
		request_kid = new_nonce_oscore_option->kid;
	}
	TRY(oscore_interactions_read_wrapper(msg_type_oscore, &token,
					     c->rrc.interactions, &request_piv,
					     &request_kid));
	/* Message type read from encrypted packet can be invalid due to external OBSERVE option change,
	   but it is sufficient enough for the interactions read wrapper to work properly,
	   as it only need to know whether the packet is any kind of response. */

	/* Calculate new nonce from oscore option - only if required by the usecase.
	   If not, nonce from the corresponding request (rcc.nonce) is used. */
	if (NULL != new_nonce_oscore_option) {
		TRY(create_nonce(&new_nonce_oscore_option->kid,
				 &new_nonce_oscore_option->piv,
				 &c->cc.common_iv, &new_nonce));
		nonce = new_nonce;
	} else {
		nonce = c->rrc.nonce;
	}

	/* compute AAD */
	uint8_t aad_buf[MAX_AAD_LEN];
	struct byte_array aad = BYTE_ARRAY_INIT(aad_buf, sizeof(aad_buf));
	TRY(create_aad(NULL, 0, c->cc.aead_alg, &request_kid, &request_piv,
		       &aad));

	/* Decrypt the ciphertext */
	TRY(oscore_cose_decrypt(ciphertext, plaintext, &nonce, &aad,
				&c->rc.recipient_key));

	/* Update nonce only after successful decryption (for handling future responses) */
	if (NULL != new_nonce_oscore_option) {
		TRY(byte_array_cpy(&c->rrc.nonce, &nonce, NONCE_LEN));
	}

	/* Generate corresponding CoAP packet */
	TRY(o_coap_pkg_generate(plaintext, input_oscore, output_coap));

	/* Handle OSCORE interactions after successful decryption.
	   Decrypted packet is used for URI Paths and message type, as original values are modified while encrypting. */
	enum o_coap_msg msg_type;
	TRY(coap_get_message_type(output_coap, &msg_type));
	BYTE_ARRAY_NEW(uri_paths, OSCORE_MAX_URI_PATH_LEN,
		       OSCORE_MAX_URI_PATH_LEN);
	TRY(uri_path_create(output_coap->options, output_coap->options_cnt,
			    uri_paths.ptr, &(uri_paths.len)));
	TRY(oscore_interactions_update_wrapper(msg_type, &token, &uri_paths,
					       c->rrc.interactions,
					       &request_piv, &request_kid));

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

	/* Make sure that given context is fresh enough to process the message. */
	TRY(check_context_freshness(c));

	/*Parse the incoming message (buf_in) into a CoAP struct*/
	memset(&oscore_packet, 0, sizeof(oscore_packet));
	TRY(coap_deserialize(&buf, &oscore_packet));

	/* Check if the packet is OSCORE packet and if so parse the OSCORE option */
	TRY(oscore_option_parser(oscore_packet.options,
				 oscore_packet.options_cnt, &oscore_option));

	/* Encrypted packet payload */
	struct byte_array *ciphertext = &oscore_packet.payload;

	/* Setup buffer for the plaintext. The plaintext is shorter than the 
	ciphertext because of the authentication tag*/
	uint32_t plaintext_bytes_len = ciphertext->len - AUTH_TAG_LEN;
	BYTE_ARRAY_NEW(plaintext, MAX_PLAINTEXT_LEN, plaintext_bytes_len);
	/* TODO plaintext can be moved inside decrypt_wrapper to simplify the code.
	   To do so, refactor of echo_val_is_fresh is needed, to operate on o_coap_packet. */

	/* Helper structure for decrypted coap packet */
	struct o_coap_packet output_coap;

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

		/* Check if the packet is replayed - in case of normal operation (replay window already synchronized).
		   It must be performed before decrypting the packet (see RFC 8613 p. 7.4). */
		if (ECHO_SYNCHRONIZED == c->rrc.echo_state_machine) {
			uint64_t ssn;
			piv2ssn(&oscore_option.piv, &ssn);
			if (!server_is_sequence_number_valid(
				    ssn, &c->rc.replay_window)) {
				PRINT_MSG("Replayed message detected!\n");
				return oscore_replay_window_protection_error;
			}
		}

		/* Decrypt packet using new nonce based on the packet */
		TRY(decrypt_wrapper(ciphertext, &plaintext, c, &oscore_option,
				    &oscore_packet, &output_coap));

		if (ECHO_REBOOT == c->rrc.echo_state_machine) {
			/* Abort the execution if this is the the first request after reboot.
			   Let the application layer know that it should prepare a special response with ECHO option
			   and prepare for verifying ECHO of the next request. */
			PRINT_MSG("Abort -- first request after reboot!\n");
			c->rrc.echo_state_machine = ECHO_VERIFY;
			return first_request_after_reboot;
		} else if (ECHO_VERIFY == c->rrc.echo_state_machine) {
			/* Next request should already have proper ECHO option for proving freshness.
			   If so, perform replay window reinitialization and start normal operation.
			   If not, repeat the whole process until normal operation can be started. */
			if (ok == echo_val_is_fresh(&c->rrc.echo_opt_val,
						    &plaintext)) {
				uint64_t ssn;
				piv2ssn(&oscore_option.piv, &ssn);
				TRY(server_replay_window_reinit(
					ssn, &c->rc.replay_window));
				c->rrc.echo_state_machine = ECHO_SYNCHRONIZED;
			} else {
				PRINT_MSG(
					"Abort -- ECHO validation failed! Repeating the challenge.\n");
				return echo_validation_failed;
			}
		} else {
			/* Normal operation - update replay window. */
			TRY_EXPECT(c->rrc.echo_state_machine,
				   ECHO_SYNCHRONIZED);
			server_replay_window_update(*oscore_option.piv.ptr,
						    &c->rc.replay_window);
		}
	} else {
		/* received any kind of response */
		if (is_observe(oscore_packet.options,
			       oscore_packet.options_cnt)) {
			if (oscore_option.piv.len != 0) {
				/*Notification with PIV received*/
				PRINT_MSG(
					"Observe notification with PIV received\n");

				TRY(replay_protection_check_notification(
					c->rc.notification_num,
					c->rc.notification_num_initialized,
					&oscore_option.piv));

				/* Decrypt packet using new nonce based on the packet */
				TRY(decrypt_wrapper(ciphertext, &plaintext, c,
						    &oscore_option,
						    &oscore_packet,
						    &output_coap));

				/*update replay protection value in context*/
				TRY(notification_number_update(
					&c->rc.notification_num,
					&c->rc.notification_num_initialized,
					&oscore_option.piv));
			} else {
				/*Notification without PIV received -- Currently not supported*/
				return not_supported_feature; //LCOV_EXCL_LINE
			}
		} else {
			/*regular response received*/
			if (oscore_option.piv.len != 0) {
				/*response with PIV*/
				TRY(decrypt_wrapper(ciphertext, &plaintext, c,
						    &oscore_option,
						    &oscore_packet,
						    &output_coap));
			} else {
				/*response without PIV*/
				TRY(decrypt_wrapper(ciphertext, &plaintext, c,
						    NULL, &oscore_packet,
						    &output_coap));
			}
		}
	}

	/*Convert to byte string*/
	return coap_serialize(&output_coap, buf_out, buf_out_len);
}
