/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef COAP_H
#define COAP_H

#include <stdint.h>

#include "oscore_coap_defines.h"
#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/* all CoAP instances are preceeded with 'o_' to show correspondence to
 * OSCORE and prevent conflicts with networking CoAP libraries 
 */
struct o_coap_header {
	uint8_t ver;
	uint8_t type;
	uint8_t TKL;
	uint8_t code;
	uint16_t MID;
};

struct o_coap_option {
	uint16_t delta;
	uint16_t len;
	uint8_t *value;
	uint16_t option_number;
};

struct oscore_option {
	uint16_t delta;
	uint8_t len;
	uint8_t *value;
	uint8_t buf[OSCORE_OPT_VALUE_LEN];
	uint16_t option_number;
};

struct o_coap_packet {
	struct o_coap_header header;
	uint8_t *token;
	uint8_t options_cnt;
	struct o_coap_option options[MAX_OPTION_COUNT];
	struct byte_array payload;
};

struct compressed_oscore_option {
	uint8_t h; /*flag bit for KID_context*/
	uint8_t k; /*flag bit for KID*/
	uint8_t n; /*bytes number of PIV*/
	struct byte_array piv; /*same as sender sequence number*/
	struct byte_array kid_context;
	struct byte_array kid;
};

/**
 * @brief   Covert a byte array to a OSCORE/CoAP struct
 * @param   in: pointer to an input message packet, in byte string format
 * @param   out: pointer to an output OSCORE packet
 * @return  err
 */
enum err coap_deserialize(struct byte_array *in, struct o_coap_packet *out);

/**
 * @brief   Converts a CoAP/OSCORE packet to a byte string
 * @param   in: input CoAP/OSCORE packet
 * @param   out_byte_string: byte string containing the OSCORE packet
 * @param   out_byte_string_len: length of the byte string
 * @return  err
 */
enum err coap_serialize(struct o_coap_packet *in, uint8_t *out_byte_string,
			uint32_t *out_byte_string_len);

/**
 * @brief   Convert input options into byte string
 * @param   options: input pointer to an array of options
 * @param   options_cnt: count number of input options
 * @param   out_byte_string: output pointer to options byte string
 * @return  err
 *
 */
enum err options_serialize(struct o_coap_option *options, uint8_t options_cnt,
			   struct byte_array *out_byte_string);

/**
 * @brief Deserializes a byte string containing options and eventually a payload
 * @param in_data: input data
 * @param opt: pointer to output options structure array
 * @param opt_cnt: count number of output options
 * @param payload: payload 
 * @return  err
 */
enum err options_deserialize(struct byte_array *in_data,
			     struct o_coap_option *opt, uint8_t *opt_cnt,
			     struct byte_array *payload);

/**
 * @brief	Checks if a packet is a request 
 * @param	packet: a pointer to a CoAP/OSCORE packet
 * @retval	true if the packet is a request else false
 */
bool is_request(struct o_coap_packet *packet);

/**
 * @brief	Returns the number of extra bytes needed wen encoding an option.
 * @param	delta_or_len option delta or option len depending on the use case
 * @retval	The needed extra bytes  
*/
uint8_t opt_extra_bytes(uint16_t delta_or_len);

/**
 * @brief Get the message type of given coap packet.
 * @param coap_packet coap packet
 * @param msg_type message type
 * @return ok or error code
 */
enum err coap_get_message_type(struct o_coap_packet *coap_packet,
			       enum o_coap_msg *msg_type);

#endif
