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
	BYTE_ARRAY_NEW(unprotected_o_coap_payload, 0, 0);

	struct o_coap_option E_options[10];
	uint8_t E_options_cnt = 0;

	/* Parse decrypted payload: code + options + unprotected CoAP payload*/
	TRY(oscore_decrypted_payload_parser(decrypted_payload, &code, E_options,
					    &E_options_cnt,
					    &unprotected_o_coap_payload));

	for (uint8_t i = 0; i < E_options_cnt; i++) {
		if (E_options[i].option_number == ECHO) {
			if (0 == memcmp(E_options[i].value, cache_val->ptr,
					cache_val->len) &&
			    cache_val->len == E_options[i].len) {
				PRINT_MSG("ECHO option check -- OK\n");
				return ok;
			} else {
				return echo_val_mismatch;
			}
		}
	}

	return no_echo_option;
}