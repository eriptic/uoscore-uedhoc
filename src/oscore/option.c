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

/**
 * @brief Securely append a substring to given buffer.
 * 
 * @param buffer Buffer to have the substring appended.
 * @param current_size Current size of the buffer content. Updated after successfull append.
 * @param max_size Memory size allocated for the buffer.
 * @param substring Substring buffer to be appended.
 * @param substring_size Substring size.
 * @return ok or error
 */
static enum err buffer_append(uint8_t *buffer, uint32_t *current_size,
			      uint32_t max_size, const uint8_t *substring,
			      uint32_t substring_size)
{
	uint8_t *destination =
		&buffer[*current_size]; //pointer to current end of the content
	uint32_t remaining_size =
		max_size -
		(*current_size); //how many bytes in the buffer are still available
	TRY(_memcpy_s(destination, remaining_size, substring, substring_size));
	*current_size += substring_size;
	return ok;
}

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

bool get_observe_value(struct o_coap_option *options, uint8_t options_cnt,
		       struct byte_array *output)
{
	if ((NULL == options) || (NULL == output)) {
		return false;
	}

	for (uint8_t i = 0; i < options_cnt; i++) {
		if (OBSERVE != options[i].option_number) {
			continue;
		}

		output->ptr = options[i].value;
		output->len = options[i].len;
		return true;
	}
	output = NULL;
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
			dest->len = options[i].len;
			return ok;
		}
	}
	return no_echo_option;
}

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

	struct byte_array remaining_bytes =
		BYTE_ARRAY_INIT(temp_payload_ptr, temp_payload_len);
	TRY(options_deserialize(&remaining_bytes, out_E_options, E_options_cnt,
				out_o_coap_payload));

	return ok;
}

enum err echo_val_is_fresh(struct byte_array *cache_val,
			   struct byte_array *decrypted_payload)
{
	uint8_t code = 0;
	struct byte_array unprotected_o_coap_payload;

	struct o_coap_option E_options[10];
	uint8_t E_options_cnt = 0;

	/* Parse decrypted payload: code + options + unprotected CoAP payload*/
	TRY(oscore_decrypted_payload_parser(decrypted_payload, &code, E_options,
					    &E_options_cnt,
					    &unprotected_o_coap_payload));

	for (uint8_t i = 0; i < E_options_cnt; i++) {
		if (E_options[i].option_number == ECHO) {
			if (cache_val->len == E_options[i].len &&
			    0 == memcmp(E_options[i].value, cache_val->ptr, cache_val->len) ) {
				PRINT_MSG("ECHO option check -- OK\n");
				return ok;
			} else {
				return echo_val_mismatch;
			}
		}
	}

	return no_echo_option;
}


enum err uri_path_create(struct o_coap_option *options, uint32_t options_size,
			 uint8_t *uri_path, uint32_t *uri_path_size)
{
	if ((NULL == options) || (NULL == uri_path) ||
	    (NULL == uri_path_size)) {
		return wrong_parameter;
	}

	uint32_t current_size = 0;
	uint32_t max_size = *uri_path_size;
	memset(uri_path, 0, max_size);

	const uint8_t delimiter = '/';
	const uint32_t delimiter_size = 1;

	for (uint32_t index = 0; index < options_size; index++) {
		struct o_coap_option *option = &options[index];
		if (URI_PATH != option->option_number) {
			continue;
		}
		if ((0 != option->len) && (NULL == option->value)) {
			return oscore_wrong_uri_path;
		}

		TRY(buffer_append(uri_path, &current_size, max_size,
				  option->value, option->len));
		TRY(buffer_append(uri_path, &current_size, max_size, &delimiter,
				  delimiter_size));
	}

	/* Remove last '/' character, or add a single one if the path is empty */
	if (current_size > 0) {
		uri_path[current_size] = 0;
		current_size--;
	} else {
		uri_path[0] = delimiter;
		current_size = delimiter_size;
	}

	*uri_path_size = current_size;
	return ok;
}