/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef OSCORE_H
#define OSCORE_H

#include <stdbool.h>
#include <stdint.h>

#include "oscore/security_context.h"
#include "oscore/supported_algorithm.h"
#include "oscore/nvm.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

/*
 * When OSCORE is used with fixed keys, i.e., no re-keying with EDHOC 
 * after reboot the SSN needs to be stored at runtime in NVM and restored 
 * at OSCORE initialization. The flowing two values are used to adjust the 
 * storing interval on the SSN. Those values may need to be adjusted by 
 * the user, see Appendix B.1.1.
 */
#ifndef K_SSN_NVM_STORE_INTERVAL
#define K_SSN_NVM_STORE_INTERVAL 10
#endif

#ifndef F_NVM_MAX_WRITE_FAILURE
#define F_NVM_MAX_WRITE_FAILURE 10
#endif

#ifndef OSCORE_MAX_PLAINTEXT_LEN
#define OSCORE_E_OPTIONS_LEN 40
#define OSCORE_COAP_PAYLOAD_LEN 1024
/* OSCORE plaintext includes CoAP frame with CoAP payload */
#define OSCORE_MAX_PLAINTEXT_LEN                                               \
	(OSCORE_COAP_PAYLOAD_LEN + OSCORE_E_OPTIONS_LEN)
#endif

#define MAX_PLAINTEXT_LEN OSCORE_MAX_PLAINTEXT_LEN
#define MAX_CIPHERTEXT_LEN (MAX_PLAINTEXT_LEN + AUTH_TAG_LEN)
#ifndef E_OPTIONS_BUFF_MAX_LEN
#define E_OPTIONS_BUFF_MAX_LEN                                                 \
	255 /* Maximal length of buffer with all encrypted CoAP options. */
#endif
#ifndef I_OPTIONS_BUFF_MAX_LEN
#define I_OPTIONS_BUFF_MAX_LEN                                                 \
	255 /* Maximal length of buffer with all not encrypted CoAP options. */
#endif
#define MAX_COAP_OPTIONS_LEN                                                   \
	((E_OPTIONS_BUFF_MAX_LEN > I_OPTIONS_BUFF_MAX_LEN) ?                   \
		 E_OPTIONS_BUFF_MAX_LEN :                                      \
		 I_OPTIONS_BUFF_MAX_LEN)

/**
 * Each endpoint derives the parameters in the security context from a
 * small set of input parameters.
 */
struct oscore_init_params {
	/*master_secret must be provided. Currently 16 byte secrets are supported*/
	const struct byte_array master_secret;
	/*sender_id must be provided*/
	const struct byte_array sender_id;
	/*recipient_id must be provided*/
	const struct byte_array recipient_id;

	/*The specification doesn't describe how the ID Context is created */
	/*When the user wants to use ID Context it has to provide it in the initialization of the client. The servers ID Context is transported in the oscore option*/
	struct byte_array id_context;
	/*master_salt is optional (default empty byte string)*/
	const struct byte_array master_salt;
	/*aead_alg is optional (default AES-CCM-16-64-128)*/
	const enum AEAD_algorithm aead_alg;
	/*kdf is optional (default HKDF-SHA-256)*/
	const enum hkdf hkdf;
	/*True if the combination of master secret and master salt are unique at every boot of the device, e.g., they are computed with EDHOC.
	If not, OSCORE_NVM_SUPPORT flag must be defined, for proper non-volatile memory management.*/
	const bool fresh_master_secret_salt;
};

/**
 * @brief Initialize security context of OSCORE, including common context, 
 * recipient context and sender context.
 * 
 * @param 	params a struct containing the initialization parameters
 * @param	context a struct containing the contexts
 * @return  err
 */
enum err oscore_context_init(struct oscore_init_params *params,
			     struct context *c);

/**
 * @brief  	Checks if the packet in buf_in is a OSCORE packet.
 * 		If so it converts it to a CoAP packet and sets the oscore_pkg to
 * 		true in order to indicate the caller function that a
 * 		OSCORE packet was received.
 * 
 * @param 	buf_in a buffer containing an incoming packet which can be 
 * 		OSCORE or CoAP packet.
 * @param 	buf_in_len length of the data in the buf_in
 * @param 	buf_out when a OSCORE packet is found and decrypted the 
 * 		resulting CoAP is saved in buf_out
 * @param 	buf_out_len length of the CoAP packet
 * @param 	c pointer to a security context
 * @return	err
 */
enum err oscore2coap(uint8_t *buf_in, uint32_t buf_in_len, uint8_t *buf_out,
		     uint32_t *buf_out_len, struct context *c);

/**
 *@brief 	Converts a CoAP packet to OSCORE packet
 *
 *@param	buf_o_coap a buffer containing a CoAP packet
 *@param	buf_o_coap_len length of the CoAP buffer
 *@param	buf_oscore a buffer where the OSCORE packet will be written
 *@param	buf_oscore_len length of the OSCORE packet
 *@param	c a struct containing the OSCORE context
 *@return	err
 */
enum err coap2oscore(uint8_t *buf_o_coap, uint32_t buf_o_coap_len,
		     uint8_t *buf_oscore, uint32_t *buf_oscore_len,
		     struct context *c);

#endif
