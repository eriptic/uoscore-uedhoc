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

#include "oscore/oscore_coap.h"
#include "oscore/option.h"

#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"
#include "common/unit_test.h"

#define OSCORE_OBSERVE_REGISTRATION_VALUE 0
#define OSCORE_OBSERVE_CANCELLATION_VALUE 1

uint8_t opt_extra_bytes(uint16_t delta_or_len)
{
	if (delta_or_len < 13) {
		return 0;
	}

	if (delta_or_len < 269) {
		return 1;
	}

	return 2;
}

enum err options_serialize(struct o_coap_option *options, uint8_t options_cnt,
			   struct byte_array *out)
{
	uint8_t delta_extra_byte = 0;
	uint8_t len_extra_byte = 0;
	uint8_t *temp_ptr = out->ptr;
	uint8_t *header_byte;

	/* Reset length */
	uint32_t out_capacity = out->len;
	out->len = 0;

	for (uint8_t i = 0; i < options_cnt; i++) {
		delta_extra_byte = opt_extra_bytes(options[i].delta);
		len_extra_byte = opt_extra_bytes(options[i].len);

		header_byte = temp_ptr;
		*header_byte = 0;

		switch (delta_extra_byte) {
		case 0:
			*(header_byte) = (uint8_t)(options[i].delta << 4);
			break;
		case 1:
			*(header_byte) = (uint8_t)(13 << 4);
			*(temp_ptr + 1) = (uint8_t)(options[i].delta - 13);
			break;
		case 2:
			*(header_byte) = (uint8_t)(14 << 4);
			uint16_t temp_delta =
				(uint16_t)(options[i].delta - 269);
			*(temp_ptr + 1) = (uint8_t)((temp_delta & 0xFF00) >> 8);
			*(temp_ptr + 2) = (uint8_t)((temp_delta & 0x00FF) >> 0);
			break;
		}

		switch (len_extra_byte) {
		case 0:
			*(header_byte) |= (uint8_t)(options[i].len);
			break;
		case 1:
			*(header_byte) |= 13;
			*(temp_ptr + delta_extra_byte + 1) =
				(uint8_t)(options[i].len - 13);
			break;
		case 2:
			*(header_byte) |= 14;
			uint16_t temp_len = (uint16_t)(options[i].len - 269);
			*(temp_ptr + delta_extra_byte + 1) =
				(uint8_t)((temp_len & 0xFF00) >> 8);
			*(temp_ptr + delta_extra_byte + 2) =
				(uint8_t)((temp_len & 0x00FF) >> 0);
			break;
		}

		/* Move to the position, where option value begins */
		temp_ptr += 1 + delta_extra_byte + len_extra_byte;
		/* Add length of current option*/
		out->len = (uint32_t)(out->len + 1 + delta_extra_byte +
				      len_extra_byte + options[i].len);
		/* Copy the byte string of current option into output*/
		if (0 != options[i].len) {
			uint32_t dest_size =
				out_capacity - (uint32_t)(temp_ptr - out->ptr);
			TRY(_memcpy_s(temp_ptr, dest_size, options[i].value,
				      options[i].len));

			temp_ptr += options[i].len;
		}
	}
	return ok;
}

enum err options_deserialize(struct byte_array *in_data,
			     struct o_coap_option *opt, uint8_t *opt_cnt,
			     struct byte_array *payload)
{
	uint8_t *temp_options_ptr = in_data->ptr;
	uint8_t temp_options_count = 0;
	uint8_t temp_option_header_len = 0;
	uint16_t temp_option_delta = 0;
	uint16_t temp_option_len = 0;
	uint16_t temp_option_number = 0;

	if (0 == in_data->len) {
		payload->len = 0;
		payload->ptr = NULL;
		*opt_cnt = 0;
		return ok;
	}

	/* Go through the in_data to find out how many options are there */
	uint16_t i = 0;
	while (i < in_data->len) {
		if (OPTION_PAYLOAD_MARKER == in_data->ptr[i]) {
			if ((in_data->len - i) < 2) {
				return not_valid_input_packet;
			}
			i++;
			payload->len = (uint32_t)in_data->len - i;
			payload->ptr = &in_data->ptr[i];
			return ok;
		}

		temp_option_header_len = 1;
		/* Parser first byte,lower 4 bits for option value length and higher 4 bits for option delta*/
		temp_option_delta = ((*temp_options_ptr) & 0xF0) >> 4;
		temp_option_len = (*temp_options_ptr) & 0x0F;

		temp_options_ptr++;

		/* Special cases for extended option delta: 13 - 1 extra delta byte, 14 - 2 extra delta bytes, 15 - reserved */
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
				(uint16_t)(((*temp_options_ptr) << 8) |
					   *(temp_options_ptr + 1)) +
				269;
			temp_options_ptr += 2;
			break;
		case 15:
			// ERROR
			return oscore_inpkt_invalid_option_delta;
			break;
		default:
			break;
		}

		/* Special cases for extended option value length: 13 - 1 extra length byte, 14 - 2 extra length bytes, 15 - reserved */
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
			temp_option_len =
				(uint16_t)(((*temp_options_ptr) << 8) |
					   (*(temp_options_ptr + 1) + 269));
			temp_options_ptr += 2;
			break;
		case 15:
			/* ERROR */
			return oscore_inpkt_invalid_optionlen;
			break;
		default:
			break;
		}

		temp_option_number = temp_option_number + temp_option_delta;
		/* Update in output options */
		opt[temp_options_count].delta = temp_option_delta;
		opt[temp_options_count].len = temp_option_len;
		opt[temp_options_count].option_number = temp_option_number;
		if (temp_option_len == 0)
			opt[temp_options_count].value = NULL;
		else
			opt[temp_options_count].value = temp_options_ptr;

		/* Update parameters*/
		i = (uint16_t)(i + temp_option_header_len + temp_option_len);
		temp_options_ptr += temp_option_len;
		if ((MAX_OPTION_COUNT - 1) > temp_options_count) {
			temp_options_count++;
		} else {
			return too_many_options;
		}
		*opt_cnt = temp_options_count;
	}
	return ok;
}

enum err coap_deserialize(struct byte_array *in, struct o_coap_packet *out)
{
	uint8_t *tmp_p = in->ptr;
	uint32_t payload_len = in->len;

	/* Read CoAP/OSCORE header (4 bytes)*/
	if (payload_len < HEADER_LEN) {
		return not_valid_input_packet;
	}
	out->options_cnt = 0;
	out->header.ver =
		((*tmp_p) & HEADER_VERSION_MASK) >> HEADER_VERSION_OFFSET;
	out->header.type = ((*tmp_p) & HEADER_TYPE_MASK) >> HEADER_TYPE_OFFSET;
	out->header.TKL = ((*tmp_p) & HEADER_TKL_MASK) >> HEADER_TKL_OFFSET;
	out->header.code = *(tmp_p + 1);
	uint16_t mid_l = *(tmp_p + 3);
	uint16_t mid_h = *(tmp_p + 2);
	out->header.MID = (uint16_t)(mid_h << 8 | mid_l);

	/* Update pointer and length*/
	tmp_p += 4;
	payload_len -= 4;

	/*Read the token, if it exists*/
	if (out->header.TKL == 0) {
		out->token = NULL;
	} else if (out->header.TKL <= 8) {
		if (out->header.TKL <= payload_len) {
			out->token = tmp_p;
		} else {
			return oscore_inpkt_invalid_tkl;
		}
	} else {
		/* ERROR: CoAP token length maximal 8 bytes */
		return oscore_inpkt_invalid_tkl;
	}
	/* Update pointer and length */
	tmp_p += out->header.TKL;
	payload_len -= out->header.TKL;

	struct byte_array remaining_bytes = BYTE_ARRAY_INIT(tmp_p, payload_len);
	TRY(options_deserialize(&remaining_bytes,
				(struct o_coap_option *)&out->options,
				&out->options_cnt, &out->payload));

	return ok;
}

enum err coap_serialize(struct o_coap_packet *in, uint8_t *out_byte_string,
			uint32_t *out_byte_string_len)
{
	uint8_t *temp_out_ptr = out_byte_string;

	/* First byte in header (version + type + token length) */
	*temp_out_ptr = (uint8_t)((in->header.ver << HEADER_VERSION_OFFSET) |
				  (in->header.type << HEADER_TYPE_OFFSET) |
				  (in->header.TKL));
	/* Following 3 bytes in header (1 byte code + 2 bytes message ID)*/
	*(temp_out_ptr + 1) = in->header.code;
	uint16_t temp_MID = in->header.MID;
	*(temp_out_ptr + 2) = (uint8_t)((temp_MID & 0xFF00) >> 8);
	*(temp_out_ptr + 3) = (uint8_t)(temp_MID & 0x00FF);

	temp_out_ptr += 4;
	/* Copy token */
	if (in->header.TKL > 0) {
		uint32_t dest_size = *out_byte_string_len -
				     (uint32_t)(temp_out_ptr - out_byte_string);
		TRY(_memcpy_s(temp_out_ptr, dest_size, in->token,
			      in->header.TKL));

		temp_out_ptr += in->header.TKL;
	}

	/* Calculate the maximal length of all options, i.e. all options have two bytes extra delta and length*/
	uint32_t opt_bytes_len = 0;
	for (uint8_t i = 0; i < in->options_cnt; i++) {
		opt_bytes_len += OPT_SERIAL_OVERHEAD + in->options[i].len;
	}

	BYTE_ARRAY_NEW(option_byte_string, MAX_COAP_OPTIONS_LEN, opt_bytes_len);

	/* Convert all OSCORE U-options structure into byte string*/
	TRY(options_serialize(in->options, in->options_cnt,
			      &option_byte_string));

	/* Copy options byte string into output*/

	uint32_t dest_size = *out_byte_string_len -
			     (uint32_t)(temp_out_ptr - out_byte_string);
	TRY(_memcpy_s(temp_out_ptr, dest_size, option_byte_string.ptr,
		      option_byte_string.len));

	temp_out_ptr += option_byte_string.len;

	/* Payload */
	if (in->payload.len != 0) {
		*temp_out_ptr = OPTION_PAYLOAD_MARKER;

		dest_size = *out_byte_string_len -
			    (uint32_t)(temp_out_ptr + 1 - out_byte_string);
		TRY(_memcpy_s(++temp_out_ptr, dest_size, in->payload.ptr,
			      in->payload.len));
	}
	*out_byte_string_len =
		(uint32_t)4 + in->header.TKL + option_byte_string.len;
	if (in->payload.len) {
		*out_byte_string_len += 1 + in->payload.len;
	}

	PRINT_ARRAY("Byte string of the converted packet", out_byte_string,
		    *out_byte_string_len);
	return ok;
}

bool is_request(struct o_coap_packet *packet)
{
	if ((CODE_CLASS_MASK & packet->header.code) == REQUEST_CLASS) {
		return true;
	} else {
		return false;
	}
}

enum err coap_get_message_type(struct o_coap_packet *coap_packet,
			       enum o_coap_msg *msg_type)
{
	if ((NULL == coap_packet) || (NULL == msg_type)) {
		return wrong_parameter;
	}

	enum o_coap_msg result;
	struct byte_array observe;
	bool observe_valid = get_observe_value(
		coap_packet->options, coap_packet->options_cnt, &observe);
	bool request = is_request(coap_packet);
	if (request) {
		// packet can be a request, a registration or a cancellation
		result = COAP_MSG_REQUEST;
		if (observe_valid) {
			if ((0 == observe.len) ||
			    ((1 == observe.len) &&
			     (OSCORE_OBSERVE_REGISTRATION_VALUE ==
			      observe.ptr[0]))) {
				/* Empty uint option is interpreted as a value 0.
				   For more info, see RFC 7252 section 3.2. */
				result = COAP_MSG_REGISTRATION;
			} else if ((1 == observe.len) &&
				   (OSCORE_OBSERVE_CANCELLATION_VALUE ==
				    observe.ptr[0])) {
				result = COAP_MSG_CANCELLATION;
			}
		}
	} else {
		// packet can be a regular response or a notification
		result = (observe_valid ? COAP_MSG_NOTIFICATION :
					  COAP_MSG_RESPONSE);
	}

	*msg_type = result;
	return ok;
}
