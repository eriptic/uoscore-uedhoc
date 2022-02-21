/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef COSE_H
#define COSE_H

#include "common/oscore_edhoc_error.h"

enum cose_context {
	Encrypt0,
	Signature1,
};

/**
 * @brief	Encodes a cose encrypt structure
 * @param	context field in the cose encrypt structure
 * @param	contex_len length of context
 * @param	protected field in the cose encrypt structure
 * @param	protected_len length of protected
 * @param	external_aad field in the cose encrypt structure
 * @param	external_aad_len length of external_aad
 * @param	out the encoded structure
 * @param	out_len length of the encoded structure
 * @retval	err error code
 */
enum err cose_enc_structure_encode(const uint8_t *context, uint32_t context_len,
				   const uint8_t *protected,
				   uint32_t protected_len,
				   const uint8_t *external_aad,
				   uint32_t external_aad_len, uint8_t *out,
				   uint32_t *out_len);

/**
 * @brief	Encodes a cose signature structure
 * @param	context field in the cose signature structure
 * @param	contex_len length of context
 * @param	protected field in the cose signature structure
 * @param	protected_len length of protected
 * @param	external_aad field in the cose signature structure
 * @param	external_aad_len length of external_aad
 * @param	payload field in the cose signature structure
 * @param	payload_len length of payload
 * @param	out the encoded structure
 * @param	out_len length of the encoded structure
 * @retval	err error code
 */
enum err cose_sig_structure_encode(const uint8_t *context, uint32_t context_len,
				   const uint8_t *protected,
				   uint32_t protected_len,
				   const uint8_t *external_aad,
				   uint32_t external_aad_len,
				   const uint8_t *payload, uint32_t payload_len,
				   uint8_t *out, uint32_t *out_len);

#endif
