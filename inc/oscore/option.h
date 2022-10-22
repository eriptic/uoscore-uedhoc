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
 * @brief Checks if an option belongs to a certain class
 * 
 * @param option_num the option number
 * @return true if the option belongs to a given class
 * @return false if the option does not belong to a given class
 */
bool option_belongs_to_class(uint16_t option_num, enum option_class class);

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
 * @brief	Checks if an array of options contains a observe option that 
 * 			indicates registration
 * @param	options pointer to an array of options. 
 * @param	options_cnt number of entries in the array
 */
bool is_observe_registration(struct o_coap_option *options,
			     uint8_t options_cnt);
#endif
