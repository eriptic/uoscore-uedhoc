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

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

#define MAX_PIV_LEN 5
#define MAX_KID_CONTEXT_LEN                                                    \
	8 /*This implementation supports Context IDs up to 8 byte*/
#define MAX_KID_LEN 7
#define MAX_AAD_LEN 30
#define MAX_INFO_LEN 50

/* Mask and offset for first byte in CoAP/OSCORE header*/
#define HEADER_LEN 4
#define HEADER_VERSION_MASK 0xC0
#define HEADER_VERSION_OFFSET 6
#define HEADER_TYPE_MASK 0x30
#define HEADER_TYPE_OFFSET 4
#define HEADER_CODE_MASK 0x0F
#define HEADER_CODE_OFFSET 0

/* Mask and offset for first byte in compressed OSCORE option*/
#define COMP_OSCORE_OPT_KIDC_H_MASK 0x10
#define COMP_OSCORE_OPT_KIDC_H_OFFSET 4
#define COMP_OSCORE_OPT_KID_K_MASK 0x08
#define COMP_OSCORE_OPT_KID_K_OFFSET 3
#define COMP_OSCORE_OPT_PIV_N_MASK 0x07
#define COMP_OSCORE_OPT_PIV_N_OFFSET 0

#define OSCORE_OPT_VALUE_LEN                                                   \
	(2 + MAX_PIV_LEN + MAX_KID_CONTEXT_LEN + MAX_KID_LEN)

#define MAX_OPTION_COUNT 20


#define TYPE_CON			0x00
#define TYPE_NON			0x01
#define TYPE_ACK			0x02
#define TYPE_RST			0x03

#define CODE_CLASS_MASK			0xe0
#define CODE_DETAIL_MASK		0x1f
#define CODE_EMPTY			0x00
#define CODE_REQ_POST			0x02
#define CODE_RESP_CHANGED		0x44

#define REQUEST_CLASS 0

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
	uint8_t len;
	uint8_t *value;
	uint8_t option_number;
};

struct oscore_option {
	uint16_t delta;
	uint8_t len;
	uint8_t *value;
	uint8_t buf[OSCORE_OPT_VALUE_LEN];
	uint8_t option_number;
};

struct o_coap_packet {
	struct o_coap_header header;
	uint8_t *token;
	uint8_t options_cnt;
	struct o_coap_option options[MAX_OPTION_COUNT];
	uint32_t payload_len;
	uint8_t *payload;
};

struct compressed_oscore_option {
	uint8_t h; /*flag bit for KID_context*/
	uint8_t k; /*flag bit for KID*/
	uint8_t n; /*bytes number of PIV*/
	struct byte_array piv; /*same as sender sequence number*/
	struct byte_array kid_context;
	struct byte_array kid;
};

struct piv_kid_context {
	struct byte_array partial_iv;
	struct byte_array kid;
	struct byte_array kid_context;
};

/**
 * @brief   Covert a byte array to a OSCORE/CoAP struct
 * @param   in: pointer input message packet, in byte string format
 * @param   out: pointer to output OSCORE packet
 * @return  err
 */
enum err buf2coap(struct byte_array *in, struct o_coap_packet *out);

/**
 * @brief   Converts a CoAP/OSCORE packet to a byte string
 * @param   in: input CoAP/OSCORE packet
 * @param   out_byte_string: byte string containing the OSCORE packet
 * @param   out_byte_string_len: length of the byte string
 * @return  err
 */
enum err coap2buf(struct o_coap_packet *in, uint8_t *out_byte_string,
		  uint32_t *out_byte_string_len);

/**
 * @brief   Convert input options into byte string
 * @param   options: input pointer to an array of options
 * @param   options_cnt: count number of input options
 * @param   out_byte_string: output pointer to options byte string
 * @return  err
 *
 */
enum err options_into_byte_string(struct o_coap_option *options,
				  uint8_t options_cnt,
				  struct byte_array *out_byte_string);
#endif
