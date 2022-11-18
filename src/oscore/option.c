/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <string.h>

#include "oscore/option.h"
#include "oscore/oscore_coap.h"

#include "common/memcpy_s.h"

bool is_class_e(uint16_t code)
{
	// blacklist, because OSCORE dictates that unknown options SHALL be processed as class E
	return code != URI_HOST && code != URI_PORT && code != OSCORE &&
	       code != PROXY_URI && code != PROXY_SCHEME;
}



bool is_observe(struct o_coap_option *options, uint8_t options_cnt)
{
	for (uint8_t i = 0; i < options_cnt; i++) {
		if (options[i].option_number == OBSERVE) {
			return true;
		}
	}
	return false;
}


enum err cache_echo_val(struct byte_array *dest, struct o_coap_option *options,
			uint8_t options_cnt)
{
	for (uint8_t i = 0; i < options_cnt; i++) {
		if (options[i].option_number == ECHO) {
			PRINT_MSG("Caching the ECHO value!\n");
			TRY(_memcpy_s(dest->ptr, dest->len, options[i].value,
				      options[i].len));
			return ok;
		}
	}
	return no_echo_option;
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
			     uint8_t *out_options_count,
			     struct byte_array *out_payload)
{
	uint8_t *temp_options_ptr = in_data;
	uint8_t temp_options_count = 0;
	uint8_t temp_option_header_len = 0;
	uint8_t temp_option_delta = 0;
	uint8_t temp_option_len = 0;
	uint8_t temp_option_number = 0;

	if (0 == in_data_len) {
		out_payload->len = 0;
		out_payload->ptr = NULL;
		*out_options_count = 0;
		return ok;
	}

	// Go through the in_data to find out how many options are there
	uint16_t i = 0;
	while (i < in_data_len) {
		if (OPTION_PAYLOAD_MARKER == in_data[i]) {
			if ((in_data_len - i) < 2) {
				return not_valid_input_packet;
			}
			i++;
			out_payload->len = (uint32_t)in_data_len - i;
			out_payload->ptr = &in_data[i];
			return ok;
		}
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
			temp_option_delta = (uint8_t)(*temp_options_ptr + 13);
			temp_options_ptr += 1;
			break;
		case 14:
			temp_option_header_len =
				(uint8_t)(temp_option_header_len + 2);
			temp_option_delta =
				(uint8_t)(((*temp_options_ptr) << 8 |
					   *(temp_options_ptr + 1)) +
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
			temp_option_len = (uint8_t)(*temp_options_ptr + 13);
			temp_options_ptr += 1;
			break;
		case 14:
			temp_option_header_len =
				(uint8_t)(temp_option_header_len + 2);
			temp_option_len = (uint8_t)(((*temp_options_ptr) << 8 |
						     *(temp_options_ptr + 1)) +
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

		// Assign options count number
		*out_options_count = temp_options_count;
	}
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
enum err oscore_decrypted_payload_parser(struct byte_array *in_payload,
					 uint8_t *out_code,
					 struct o_coap_option *out_E_options,
					 uint8_t *E_options_cnt,
					 struct byte_array *out_o_coap_payload)
{
	uint8_t *temp_payload_ptr = in_payload->ptr;
	uint32_t temp_payload_len = in_payload->len;

	/* Code */
	*out_code = *(temp_payload_ptr++);
	temp_payload_len--;

	TRY(oscore_packet_options_parser(
		temp_payload_ptr, (uint16_t)temp_payload_len, out_E_options,
		E_options_cnt, out_o_coap_payload));

	return ok;
}

enum err echo_val_is_fresh(struct byte_array *cache_val,
			   struct byte_array *decrypted_payload)
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

	for (uint8_t i = 0; i < E_options_cnt; i++) {
		if (E_options[i].option_number == ECHO) {
			if (cache_val->len == E_options[i].len &&
			    0 == memcmp(E_options[i].value, cache_val->ptr,
					cache_val->len)) {
				PRINT_MSG("ECHO option check -- OK\n");
				return ok;
			} else {
				return echo_val_mismatch;
			}
		}
	}

	return no_echo_option;
}