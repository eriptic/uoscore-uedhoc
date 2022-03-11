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

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

/**
 * @brief Parse all received options to find the OSCORE_option. If it doesn't  * have OSCORE option, then this packet is a normal CoAP. If it does have, it's * an OSCORE packet, and then parse the compressed OSCORE_option value to get  * value of PIV, KID and KID context of the client.
 * @param in: input OSCORE packet
 * @param out: pointer output compressed OSCORE_option
 * @return error types or is or not OSCORE packet
 */
static inline enum err
oscore_option_parser(struct o_coap_packet *in,
		     struct compressed_oscore_option *out, bool *oscore_pkt)
{
	uint8_t temp_option_count = in->options_cnt;
	struct o_coap_option *temp_options = in->options;
	uint8_t temp_option_num = 0;
	uint8_t *temp_current_option_value_ptr;
	uint8_t temp_kid_len = 0;

	*oscore_pkt = false;

	for (uint8_t i = 0; i < temp_option_count; i++) {
		temp_option_num = temp_options[i].option_number;
		temp_kid_len = temp_options[i].len;

		/* Check current option is OSCORE_option or not */
		if (temp_option_num == COAP_OPTION_OSCORE) {
			if (temp_options[i].len == 0) {
				/* No OSCORE option value*/
				out->h = 0;
				out->k = 0;
				out->n = 0;
				//				out->KID_len = 0;
				//				out->KIDC_len = 0;
				//				out->PIV = NULL;
				//				out->KID = NULL;
				//				out->KID_context = NULL;
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
							  (out->kid_context.len + 1));
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

			*oscore_pkt = true;
		}
	}

	return ok;
}

/**
 * @brief Decrypt the OSCORE payload (ciphertext)
 * @param out_plaintext: output plaintext
 * @param received_piv_kid_context: received PIV, KID and KID context, will be used to calculate AEAD nonce and AAD
 * @param oscore_packet: complete OSCORE packet which contains the ciphertext to be decrypted
 * @return void
 */
static inline enum err payload_decrypt(struct context *c,
				       struct byte_array *out_plaintext,
				       struct o_coap_packet *oscore_packet)
{
	struct byte_array oscore_ciphertext = {
		.len = oscore_packet->payload_len,
		.ptr = oscore_packet->payload,
	};
	return oscore_cose_decrypt(&oscore_ciphertext, out_plaintext, &c->rrc.nonce,
			    &c->rrc.aad, &c->rc.recipient_key);
}

/**
 * @brief Reorder E-options and other U-options, and update their delta, and combine them all to normal CoAP packet
 * @param in_oscore_packet: input OSCORE, which contains U-options
 * @param E_options: input pointer to E-options array
 * @param E_options_cnt: count number of input E-options
 * @param out: output pointer to CoAP packet, which will have all reordered options
 * @return ok or error code
 */
static inline enum err
options_from_oscore_reorder(struct o_coap_packet *in_oscore_packet,
			    struct o_coap_option *E_options,
			    uint8_t E_options_cnt, struct o_coap_packet *out)
{
	uint16_t temp_delta_sum = 0;
	uint8_t temp_opt_cnt =
		(uint8_t)(in_oscore_packet->options_cnt + E_options_cnt);
	uint8_t o_coap_opt_cnt = (uint8_t)(temp_opt_cnt - 1);

	/* Get all option numbers */
	if (o_coap_opt_cnt > 0) {
		TRY(check_buffer_size(MAX_OPTION_COUNT, o_coap_opt_cnt));
		uint8_t temp_opt_number[MAX_OPTION_COUNT];
		memset(temp_opt_number, 0, o_coap_opt_cnt);

		/* Get all option numbers but discard OSCORE option */
		uint8_t j = 0;
		for (uint8_t i = 0; i < o_coap_opt_cnt + 1; i++) {
			if (i < in_oscore_packet->options_cnt) {
				if (in_oscore_packet->options[i].option_number !=
				    COAP_OPTION_OSCORE)
					temp_opt_number[j++] =
						in_oscore_packet->options[i]
							.option_number;
			} else {
				temp_opt_number[j++] =
					E_options[i -
						  in_oscore_packet->options_cnt]
						.option_number;
			}
		}

		/* Reorder the option numbers from minimum to maximum */
		// uint8_t min_opt_number;
		for (uint8_t i = 0; i < o_coap_opt_cnt; i++) {
			uint8_t ipp = (uint8_t)(i + 1);
			for (uint8_t k = ipp; k < o_coap_opt_cnt; k++) {
				if (temp_opt_number[i] > temp_opt_number[k]) {
					uint8_t temp;
					temp = temp_opt_number[i];
					temp_opt_number[i] = temp_opt_number[k];
					temp_opt_number[k] = temp;
				}
			}
		}

		/* Reset output CoAP options count */
		out->options_cnt = 0;

		/* Copy all U-options and E-options in increasing number sequence*/
		uint8_t U_opt_idx = 0;
		uint8_t E_opt_idx = 0;
		for (uint8_t i = 0; i < o_coap_opt_cnt; i++) {
			if (temp_opt_number[i] ==
			    in_oscore_packet->options[U_opt_idx].option_number) {
				out->options[out->options_cnt].delta =
					(uint16_t)(in_oscore_packet
							   ->options[U_opt_idx]
							   .option_number -
						   temp_delta_sum);
				out->options[out->options_cnt].len =
					in_oscore_packet->options[U_opt_idx].len;
				out->options[out->options_cnt].option_number =
					in_oscore_packet->options[U_opt_idx]
						.option_number;
				out->options[out->options_cnt].value =
					in_oscore_packet->options[U_opt_idx]
						.value;

				temp_delta_sum =
					(uint16_t)(temp_delta_sum +
						   out->options[out->options_cnt]
							   .delta);
				out->options_cnt++;
				U_opt_idx++;
				continue;
			} else if (temp_opt_number[i] ==
				   E_options[E_opt_idx].option_number) {
				out->options[out->options_cnt].delta =
					(uint16_t)(E_options[E_opt_idx]
							   .option_number -
						   temp_delta_sum);
				out->options[out->options_cnt].len =
					E_options[E_opt_idx].len;
				out->options[out->options_cnt].option_number =
					E_options[E_opt_idx].option_number;
				out->options[out->options_cnt].value =
					E_options[E_opt_idx].value;

				temp_delta_sum =
					(uint16_t)(temp_delta_sum +
						   out->options[out->options_cnt]
							   .delta);
				out->options_cnt++;
				E_opt_idx++;
				continue;
			}
		}
	} else {
		/* No any options! */
		out->options_cnt = 0;
	}
	return ok;
}

/**
 * @brief Parse incoming options byte string into options structure
 * @param in_data: pointer to input data in byte string format
 * @param in_data_len: length of input byte string
 * @param out_options: pointer to output options structure array
 * @param out_options_count: count number of output options
 * @return  err
 */
static inline enum err
oscore_packet_options_parser(uint8_t *in_data, uint16_t in_data_len,
			     struct o_coap_option *out_options,
			     uint8_t *out_options_count)
{
	uint8_t *temp_options_ptr = in_data;
	uint8_t temp_options_count = 0;
	uint8_t temp_option_header_len = 0;
	uint8_t temp_option_delta = 0;
	uint8_t temp_option_len = 0;
	uint8_t temp_option_number = 0;

	// Go through the in_data to find out how many options are there
	uint16_t i = 0;
	while (i < in_data_len) {
		temp_option_header_len = 1;
		// Parser first byte,lower 4 bits for option value length and higher 4 bits for option delta
		temp_option_delta = ((*temp_options_ptr) & 0xF0) >> 4;
		temp_option_len = (*temp_options_ptr) & 0x0F;

		temp_options_ptr++;

		// Special cases for extended option delta: 13 - 1 extra delta byte, 14 - 2 extra delta bytes, 15 - reserved
		switch (temp_option_delta) {
		case 13:
			temp_option_header_len =
				(uint8_t)(temp_option_header_len + 1);
			temp_option_delta = (uint8_t)(*temp_options_ptr - 13);
			temp_options_ptr += 1;
			break;
		case 14:
			temp_option_header_len =
				(uint8_t)(temp_option_header_len + 2);
			temp_option_delta =
				(uint8_t)(((*temp_options_ptr) << 8 |
					   *(temp_options_ptr + 1)) -
					  269);
			temp_options_ptr += 2;
			break;
		case 15:
			// ERROR
			return oscore_inpkt_invalid_option_delta;
			break;
		default:
			break;
		}

		// Special cases for extended option value length: 13 - 1 extra length byte, 14 - 2 extra length bytes, 15 - reserved
		switch (temp_option_len) {
		case 13:
			temp_option_header_len =
				(uint8_t)(temp_option_header_len + 1);
			temp_option_len = (uint8_t)(*temp_options_ptr - 13);
			temp_options_ptr += 1;
			break;
		case 14:
			temp_option_header_len =
				(uint8_t)(temp_option_header_len + 2);
			temp_option_len = (uint8_t)(((*temp_options_ptr) << 8 |
						     *(temp_options_ptr + 1)) -
						    269);
			temp_options_ptr += 2;
			break;
		case 15:
			// ERROR
			return oscore_inpkt_invalid_optionlen;
			break;
		default:
			break;
		}

		temp_option_number =
			(uint8_t)(temp_option_number + temp_option_delta);
		// Update in output options
		out_options[temp_options_count].delta = temp_option_delta;
		out_options[temp_options_count].len = temp_option_len;
		out_options[temp_options_count].option_number =
			temp_option_number;
		if (temp_option_len == 0)
			out_options[temp_options_count].value = NULL;
		else
			out_options[temp_options_count].value =
				temp_options_ptr;

		// Update parameters
		i = (uint16_t)(i + temp_option_header_len + temp_option_len);
		temp_options_ptr += temp_option_len;
		temp_options_count++;
	}

	// Assign options count number
	*out_options_count = temp_options_count;

	return ok;
}

/**
 * @brief Parse the decrypted OSCORE payload into code, E-options and original unprotected CoAP payload
 * @param in_payload: input decrypted payload
 * @param out_code: pointer to code number of the request
 * @param out_E_options: output pointer to an array of E-options
 * @param E_options_cnt: count number of E-options
 * @param out_o_coap_payload: output pointer original unprotected CoAP payload
 * @return  err
 */
static inline enum err oscore_decrypted_payload_parser(
	struct byte_array *in_payload, uint8_t *out_code,
	struct o_coap_option *out_E_options, uint8_t *E_options_cnt,
	struct byte_array *out_o_coap_payload)
{
	uint8_t *temp_payload_ptr = in_payload->ptr;
	uint32_t temp_payload_len = in_payload->len;

	/* Code */
	*out_code = *(temp_payload_ptr++);
	temp_payload_len--;

	/* Check whether E-options exists */
	if (*temp_payload_ptr == 0xFF || temp_payload_len == 0) {
		*E_options_cnt = 0;
	} else {
		uint8_t *temp_option_ptr = temp_payload_ptr;
		/* Length of E-options byte string*/
		uint16_t options_len = 0;

		/* Move the temp_ptr to the original unprotected payload */
		while (*temp_payload_ptr != 0xFF && temp_payload_len != 0) {
			temp_payload_len--;
			temp_payload_ptr++;
			options_len++;
		}

		/* Parser all options */
		if (options_len > 0) {
			TRY(oscore_packet_options_parser(
				temp_option_ptr, options_len, out_E_options,
				E_options_cnt));

		} else
			*E_options_cnt = 0;
	}

	/* Unprotected CoAP payload */
	++temp_payload_ptr;
	if (temp_payload_len == 0) {
		out_o_coap_payload->len = 0;
		out_o_coap_payload->ptr = NULL;
	} else {
		/* Minus byte of 0xFF */
		out_o_coap_payload->len = (uint32_t)(temp_payload_len - 1);
		out_o_coap_payload->ptr = temp_payload_ptr;
	}

	return ok;
}

/**
 * @brief Generate CoAP packet from OSCORE packet
 * @param decrypted_payload: decrypted OSCORE payload, which contains code, E-options and original unprotected CoAP payload
 * @param in_oscore_packet:  input OSCORE packet
 * @param out: pointer to output CoAP packet
 * @return
 */
static inline enum err
o_coap_pkg_generate(struct byte_array *decrypted_payload,
		    struct o_coap_packet *in_oscore_packet,
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
	out->header.ver = in_oscore_packet->header.ver;
	out->header.type = in_oscore_packet->header.type;
	out->header.TKL = in_oscore_packet->header.TKL;
	out->header.code = code;
	out->header.MID = in_oscore_packet->header.MID;

	/* Token */
	if (in_oscore_packet->header.TKL == 0)
		out->token = NULL;
	else
		out->token = in_oscore_packet->token;

	/* Payload */
	out->payload_len = unprotected_o_coap_payload.len;
	if (unprotected_o_coap_payload.len == 0)
		out->payload = NULL;
	else
		out->payload = unprotected_o_coap_payload.ptr;

	/* reorder all options, and copy it to output coap packet */
	TRY(options_from_oscore_reorder(in_oscore_packet, E_options,
					E_options_cnt, out));
	return ok;
}

static bool is_request(struct o_coap_packet *packet)
{
	if ((CODE_CLASS_MASK & packet->header.code) == REQUEST_CLASS) {
		return true;
	} else {
		return false;
	}
}

static inline enum err replay_check(uint64_t sender_sequence_number,
				    uint64_t *replay_window,
				    uint8_t replay_window_len)
{
	bool first_run = true;

	if (first_run) {
		first_run = false;
		return ok;
	} else {
		/*if the sender sequence number is bigger than the 
		right most element -> all good */
		if (sender_sequence_number >
		    replay_window[replay_window_len - 1]) {
			return ok;
		}

		/*if the sender sequence number is smaller than the 
		left most element -> a replay is detected*/
		if (sender_sequence_number < replay_window[0]) {
			return replayed_packed_received;
		}

		/*if the sender sequence number is in the replay window
		-> a replay is detected*/
		for (uint8_t i = 0; i < replay_window_len; i++) {
			if (sender_sequence_number == replay_window[i]) {
				return replayed_packed_received;
			}
		}
	}

	return ok;
}

static void insert_sender_seq_number(uint64_t sender_seq_number,
				     uint64_t *replay_window, uint8_t position)
{
	/*shift all old values to the left*/
	for (uint8_t j = 0; j < position; j++) {
		replay_window[j] = replay_window[j + 1];
	}
	/*insert the new sender sequence number at a given position*/
	replay_window[position] = sender_seq_number;
}

static void update_replay_window(uint64_t sender_seq_number,
				 uint64_t *replay_window,
				 uint8_t replay_window_len)
{
	for (uint8_t i = 0; i < replay_window_len - 1; i++) {
		if ((replay_window[i] < sender_seq_number) &&
		    (sender_seq_number < replay_window[i + 1])) {
			insert_sender_seq_number(sender_seq_number,
						 replay_window, i);
			PRINT_ARRAY("Replay window:", (uint8_t *)replay_window,
				    (uint32_t)(replay_window_len *
					       sizeof(replay_window[0])));
			return;
		}
	}
	insert_sender_seq_number(sender_seq_number, replay_window,
				 (uint8_t)(replay_window_len - 1));
	PRINT_ARRAY("Replay window:", (uint8_t *)replay_window,
		    (uint32_t)(replay_window_len * sizeof(replay_window[0])));
}

enum err oscore2coap(uint8_t *buf_in, uint32_t buf_in_len, uint8_t *buf_out,
		     uint32_t *buf_out_len, bool *oscore_pkg_flag,
		     struct context *c)
{
	enum err r = ok;
	struct o_coap_packet oscore_packet;
	struct compressed_oscore_option oscore_option;
	struct byte_array buf;

	PRINT_MSG("\n\n\noscore2coap***************************************\n");
	PRINT_ARRAY("Input OSCORE packet", buf_in, buf_in_len);

	buf.ptr = buf_in;
	buf.len = buf_in_len;

	/*Parse the incoming message (buf_in) into a CoAP struct*/
	TRY(buf2coap(&buf, &oscore_packet));

	/* Check if the packet is OSCORE packet and if so parse the OSCORE option */
	TRY(oscore_option_parser(&oscore_packet, &oscore_option,
				 oscore_pkg_flag));

	/* If the incoming packet is OSCORE packet -- analyze and and decrypt it. */
	if (*oscore_pkg_flag) {
		/*In requests the OSCORE packet contains at least a KID = sender ID 
        and eventually sender sequence number*/
		if (is_request(&oscore_packet)) {
			/*Check that the recipient context c->rc has a  Recipient ID that
			 matches the received with the oscore option KID (Sender ID).
			 If this is not true return an error which indicates the caller
			 application to tray another context. This is useful when the caller
			 app doesn't know in advance to which context an incoming packet 
             belongs.*/
			if (!array_equals(&c->rc.recipient_id,
					  &oscore_option.kid)) {
				return oscore_kid_recipent_id_mismatch;
			}

			/*check is the packet is replayed*/
			TRY(replay_check(*oscore_option.piv.ptr,
					 c->rc.replay_window,
					 c->rc.replay_window_len));

			/*If this is a request message we need to calculate the nonce, aad 
            and eventually update the Common IV, Sender and Recipient Keys*/
			TRY(context_update(
				SERVER,
				(struct o_coap_option *)&oscore_packet.options,
				oscore_packet.options_cnt, &oscore_option.piv,
				&oscore_option.kid_context, c));
		}

		/* Setup buffer for the plaintext. The plaintext is shorter than the ciphertext because of the authentication tag*/
		uint32_t plaintext_bytes_len =
			oscore_packet.payload_len - AUTH_TAG_LEN;
		TRY(check_buffer_size(MAX_PLAINTEXT_LEN, plaintext_bytes_len));
		uint8_t plaintext_bytes[MAX_PLAINTEXT_LEN];
		struct byte_array plaintext = {
			.len = plaintext_bytes_len,
			.ptr = plaintext_bytes,
		};

		/* Decrypt payload */
		r = payload_decrypt(c, &plaintext, &oscore_packet);
		if (r == ok) {
			/*update the replay window after the decryption*/
			if (is_request(&oscore_packet)) {
				update_replay_window(*oscore_option.piv.ptr,
						     c->rc.replay_window,
						     c->rc.replay_window_len);
			}
		} else {
			return r;
		}

		/* Generate corresponding CoAP packet */
		struct o_coap_packet o_coap_packet;
		TRY(o_coap_pkg_generate(&plaintext, &oscore_packet,
					&o_coap_packet));

		/*Convert to byte string*/
		r = coap2buf(&o_coap_packet, buf_out, buf_out_len);
	}
	return r;
}
