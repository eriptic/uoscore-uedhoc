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
#include "common/byte_array.h"

enum cose_context {
	Encrypt0,
	Signature1,
};

/**
 * @brief			Encodes a COSE encrypt structure.
 * 
 * @param[in] context 		Context field in the COSE encrypt structure.
 * @param[in] protected 	Protected field in the COSE encrypt structure.
 * @param[in] external_aad 	External_aad field in the COSE encrypt structure
 * @param[out] out 		The result.
 * @retval			Ok or error code.
 */
enum err cose_enc_structure_encode(const struct byte_array *context,
				   const struct byte_array *protected,
				   const struct byte_array *external_aad,
				   struct byte_array *out);

/**
 * @brief			Encodes a COSE signature structure.
 * 
 * @param[in] context 		Context field in the COSE signature structure.
 * @param[in] protected 	Protected field in the COSE signature structure.
 * @param[in] external_aad 	External_aad field in the COSE signature 
 * 				structure.
 * @param[in] payload 		Payload field in the COSE signature structure.
 * @param[out] out 		The encoded structure.
 * @retval			Ok or error code.
 */
enum err cose_sig_structure_encode(const struct byte_array *context,
				   const struct byte_array *protected,
				   const struct byte_array *external_aad,
				   const struct byte_array *payload,
				   struct byte_array *out);

#endif
