/*
   Copyright (c) 2023 Assa Abloy. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef OSCORE_COAP_DEFINES_H
#define OSCORE_COAP_DEFINES_H

#define MAX_TOKEN_LEN 8
#define MAX_PIV_LEN 5
#define MAX_KID_CONTEXT_LEN                                                    \
	8 /*This implementation supports Context IDs up to 8 byte*/
#define MAX_KID_LEN 8
#define MAX_AAD_LEN 30
#define MAX_INFO_LEN 50
#define MAX_PIV_FIELD_VALUE                                                    \
	0xFFFFFFFFFF /* maximum possible value of SSN/PIV field is 2^40-1, according to RFC 8613 p. 7.2.1.*/

/**
 * @brief Maximum URI Path (resource name) size in bytes.
 */
#ifndef OSCORE_MAX_URI_PATH_LEN
#define OSCORE_MAX_URI_PATH_LEN 30
#endif

/* Mask and offset for first byte in CoAP/OSCORE header*/
#define HEADER_LEN 4
#define HEADER_VERSION_MASK 0xC0
#define HEADER_VERSION_OFFSET 6
#define HEADER_TYPE_MASK 0x30
#define HEADER_TYPE_OFFSET 4
#define HEADER_TKL_MASK 0x0F
#define HEADER_TKL_OFFSET 0

/* Mask and offset for first byte in compressed OSCORE option*/
#define COMP_OSCORE_OPT_KIDC_H_MASK 0x10
#define COMP_OSCORE_OPT_KIDC_H_OFFSET 4
#define COMP_OSCORE_OPT_KID_K_MASK 0x08
#define COMP_OSCORE_OPT_KID_K_OFFSET 3
#define COMP_OSCORE_OPT_PIV_N_MASK 0x07
#define COMP_OSCORE_OPT_PIV_N_OFFSET 0

#define ECHO_OPT_VALUE_LEN 12 /*see RFC9175 Appendix A.2*/
#define OSCORE_OPT_VALUE_LEN                                                   \
	(2 + MAX_PIV_LEN + MAX_KID_CONTEXT_LEN + MAX_KID_LEN)

#define TYPE_CON 0x00
#define TYPE_NON 0x01
#define TYPE_ACK 0x02
#define TYPE_RST 0x03

#define CODE_CLASS_MASK 0xe0
#define CODE_DETAIL_MASK 0x1f
#define CODE_EMPTY 0x00
#define CODE_REQ_GET 0x01
#define CODE_REQ_POST 0x02
#define CODE_REQ_FETCH 0x05
#define CODE_RESP_CHANGED 0x44
#define CODE_RESP_CONTENT 0x45
#define CODE_RESP_UNAUTHORIZED 0x81
#define REQUEST_CLASS 0x00

#define OPTION_PAYLOAD_MARKER 0xFF

#define MAX_OPTION_COUNT 20
#define MAX_E_OPTION_COUNT 10

/**
 * @brief Possible coap message types.
 */
enum o_coap_msg {
	COAP_MSG_REQUEST = 0, /* Regular request */
	COAP_MSG_REGISTRATION, /* Request with OBSERVE option set to 0 */
	COAP_MSG_CANCELLATION, /* Request with OBSERVE option set to 1 */
	COAP_MSG_RESPONSE, /* Regular response */
	COAP_MSG_NOTIFICATION, /* Response with OBSERVE option */
};

#endif
