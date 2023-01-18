/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef AAD_H
#define AAD_H

#include "option.h"
#include "supported_algorithm.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief   Serialize given parameters into the AAD structure.
 * @param   options CoAP Options to include in AAD (only Class 
 *          I Options will be included)
 * @param   opt_num Number of options
 * @param   aead_alg AEAD Algorithm to use
 * @param   request_kid in the request
 * @param   request_piv in the request
 * @param   out out-array. Must have the exact length as 
 *          provided by `aad_length`.
 * @return err
 */
enum err create_aad(struct o_coap_option *options, uint16_t opt_num,
		    enum AEAD_algorithm aead_alg,
		    struct byte_array *request_kid,
		    struct byte_array *request_piv, struct byte_array *out);

#endif
