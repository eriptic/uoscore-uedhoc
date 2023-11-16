/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef HKDF_INFO_H
#define HKDF_INFO_H

#include "security_context.h"
#include "supported_algorithm.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief   Encodes the HKDF Info as defined by OSCORE into the out-array
 * @param   id "Sender ID or Recipient ID when deriving keys and the empty 
 *          byte string when deriving the Common IV"
 * @param   id_context ID Context
 * @param   aead_alg AEAD Algorithm
 * @param   type type of operation this HKDF Info is going to be used for
 * @param   out out-array. Must have a length of exactly the value returned 
 *          in the out-parameter by `hkdf_info_len`.
 * @return  err
 */
enum err oscore_create_hkdf_info(struct byte_array *id,
				 struct byte_array *id_context,
				 enum AEAD_algorithm aead_alg,
				 enum derive_type type, struct byte_array *out);

#endif
