/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef OPTION_H
#define OPTION_H

#include <stdint.h>

#include "oscore_coap.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

#define OPT_SERIAL_OVERHEAD 5

enum o_num {
	IF_MATCH = 1,
	URI_HOST = 3,
	ETAG = 4,
	IF_NONE_MATCH = 5,
	OBSERVE = 6,
	URI_PORT = 7,
	LOCATION_PATH = 8,
	OSCORE = 9,
	URI_PATH = 11,
	CONTENT_FORMAT = 12,
	MAX_AGE = 14,
	URI_QUERY = 15,
	ACCEPT = 17,
	LOCATION_QUERY = 20,
	BLOCK2 = 23,
	BLOCK1 = 27,
	SIZE2 = 28,
	PROXY_URI = 35,
	PROXY_SCHEME = 39,
	SIZE1 = 60,
	ECHO = 252,
};

enum option_class {
	CLASS_U, /*unprotected*/
	CLASS_I, /*integrity protected only*/
	CLASS_E, /*encrypted and integrity protected*/
};

/**
 * @brief   Returns whether the CoAP Option with given `code` is a 
 *          Class E Option (encrypted)
 * @param   code CoAP Option's code
 * @return  true if the option is a Class E Option
 */
bool is_class_e(uint16_t code);

/**
 * @brief   Parses the passed options until the payload marker of end of 
 *          array and writes them into @a out.
 *          Returns the number of parsed options and writes the number of 
 *          bytes consumed into @a offset_out. If @a out is NULL, this function 
 *          doesn't write parsed options, but still returns the number 
 *          of options.
 * @param   options
 * @param   out Out-array. Must be at least `num_options(...)` long or NULL.
 * @param   offset_out Pointer to write byte-length of options into. 
 *          Can be NULL.
 * @return  err
 */
enum err decode_options(struct byte_array options, struct o_coap_option *out,
			uint16_t *offset_out);

/**
 * @brief   Returns the length in bytes of the serialized options 
 *          of given class.
 * @param   options CoAP Option array containing all options 
 *          (possibly including ones of other classes)
 * @param   opt_num Number of CoAP options in @a options.
 * @param   class Class of the options to encode
 * @return  length in bytes
 */
uint32_t encoded_option_len(struct o_coap_option *options, uint16_t opt_num,
			    enum option_class class);

/**
 * @brief   Encodes all options in given array having given class.
 * @param   options CoAP Option array containing all options 
 *          (possibly including ones of other classes)
 * @param   opt_num Number of CoAP options in @a options.
 * @param   class Class of the options to encode
 * @param   out out-pointer. Must be at least `encoded_option_len(...)` 
 *          bytes long.
 * @param   out_buf_len the length of of the out buffer
 * @return  err
 */
enum err encode_options(struct o_coap_option *options, uint16_t opt_num,
			enum option_class class, uint8_t *out,
			uint32_t out_buf_len);

/**
 * @brief	Checks if an array of options contains a observe option
 * @param	options pointer to an array of options. This can be an array 
 * 			containing all options of an input CoAP packet, the inner or 
 * 			outer options of an OSCORE packet. This is because the observe 
 * 			option is contained in all of the above collections
 * @param	options_cnt number of entries in the array
 */
bool is_observe(struct o_coap_option *options, uint8_t options_cnt);

/**
 * @brief Returns the value of OBSERVE option.
 * @param options Options array.
 * @param options_cnt Number of entries in the array.
 * @param output Pointer to byte array which will point to the value buffer.
 *               Set to NULL if not found.
 * @return true if found, false if not.
 */
bool get_observe_value(struct o_coap_option *options, uint8_t options_cnt,
		       struct byte_array *output);

/**
 * @brief	Saves an ECHO option value to be compared later with an ECHO value 
 * 			received from the client.
 * @param	dest location to save the ECHO value
 * @param	options	E options
 * @param	options_cnt the number of the options
 * @retval	error code
 * 
*/
enum err cache_echo_val(struct byte_array *dest, struct o_coap_option *options,
			uint8_t options_cnt);

/**
 * @brief	Checks if an ECHO value is fresh. It takes a decrypted payload and 
 * 			search in it for an ECHO option. If such is find it compares it 
 * 			to the cached one.
 * @param	cache_value previously saved ECHO value
 * @param	decrypted_payload the decrypted payload of the message
 * @retval	error code
*/
enum err echo_val_is_fresh(struct byte_array *cache_val,
			   struct byte_array *decrypted_payload);

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
					 struct byte_array *out_o_coap_payload);

/**
 * @brief Compose URI Path (resource name) from given options array.
 * Implemented based on RFC7252 section 6.5 (partial compliance limited to the library's needs only).
 * @param options Options array.
 * @param options_size Options array size (number of items).
 * @param uri_path Output pointer to write composed URI Path into.
 * @param uri_path_size Maximum size of the allocated URI Path buffer (input), actual URI Path length (output).
 * @return ok or error code
 */
enum err uri_path_create(struct o_coap_option *options, uint32_t options_size,
			 uint8_t *uri_path, uint32_t *uri_path_size);

#endif
