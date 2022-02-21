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

#include "common/memcpy_s.h"

bool is_class_e(uint16_t code)
{
	// blacklist, because OSCORE dictates that unknown options SHALL be processed as class E
	return code != COAP_OPTION_URI_HOST && code != COAP_OPTION_URI_PORT &&
	       code != COAP_OPTION_OSCORE && code != COAP_OPTION_PROXY_URI &&
	       code != COAP_OPTION_PROXY_SCHEME;
}



bool option_belongs_to_class(uint16_t option_num, enum option_class class)
{
	switch (class) {
	case CLASS_I:
		/* "Note: There are currently no Class I option message fields defined." */
		return false;
	case CLASS_E:
		return is_class_e(option_num);
	default:
		break;
	}
	return false;
}

/**
 * @brief   Returns the length of an option field
 * @param   value option value
 * @retval  the length 
 */
static uint8_t option_field_len(uint16_t value)
{
	if (value < 13) {
		return 0;
	} else if (value < 269) {
		return 1;
	} else {
		return 2;
	}
}

uint32_t encoded_option_len(struct o_coap_option *options, uint16_t opt_num,
			    enum option_class class)
{
	uint32_t len = 0;
	uint16_t total_delta = 0;
	for (int i = 0; i < opt_num; i++) {
		total_delta = (uint16_t)(total_delta + options[i].delta);
		uint16_t code = total_delta;
		if (!option_belongs_to_class(code, class)) {
			continue;
		}

		len = (uint32_t)(len + 1 + option_field_len(options[i].delta) +
				 option_field_len(options[i].len) +
				 options[i].len);
	}
	return len;
}

enum err encode_options(struct o_coap_option *options, uint16_t opt_num,
			enum option_class class, uint8_t *out,
			uint32_t out_buf_len)
{

	uint32_t index = 0;
	uint16_t skipped_delta = 0;
	for (int i = 0; i < opt_num; i++) {
		// skip options which aren't of requested class
		uint16_t delta = (uint16_t)(options[i].delta + skipped_delta);
		
		if (!option_belongs_to_class(delta, class)) {
			skipped_delta =
				(uint16_t)(skipped_delta + options[i].delta);
			continue;
		}
		skipped_delta = 0;

		struct o_coap_option option = options[i];

		uint8_t length = option.len;
		uint8_t delta_length_field = 0;
		uint8_t delta_len = option_field_len(delta);
		uint8_t length_len = option_field_len(length);
		// delta
		if (delta_len == 0) {
			delta_length_field |= (uint8_t)(delta << 4);
		} else if (delta_len == 1) {
			delta_length_field |= 13 << 4;
			out[index + 1] = (uint8_t)(delta - 13);
		} else {
			//assert_eq(delta_len, 2);
			delta_length_field |= 14 << 4;
			out[index + 1] = (uint8_t)(((delta - 269) >> 8) & 0xff);
			out[index + 2] = (uint8_t)(((delta - 269) >> 0) & 0xff);
		}
		// length
		if (length_len == 0) {
			delta_length_field |= length;
		} else if (length_len == 1) {
			delta_length_field |= 13;
			out[index + delta_len + 1] = (uint8_t)(length - 13);
		} else {
			//assert_eq(length_len, 2);
			delta_length_field |= 14;
			out[index + delta_len + 1] =
				(uint8_t)(((length - 269) >> 8) & 0xff);
			out[index + delta_len + 2] =
				(uint8_t)(((length - 269) >> 0) & 0xff);
		}
		out[index] = delta_length_field;
		index = (uint32_t)(index + 1 + delta_len + length_len);
		// value
		TRY(_memcpy_s(&out[index], (out_buf_len - index),
			      &option.value[0], length));

		index += length;
	}
	return ok;
}
