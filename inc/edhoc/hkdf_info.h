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

#include "suites.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

enum info_label {
	KEYSTREAM_2 = 0,
	SALT_3e2m = 1,
	MAC_2 = 2,
	K_3 = 3,
	IV_3 = 4,
	SALT_4e3m = 5,
	MAC_3 = 6,
	PRK_out = 7,
	K_4 = 8,
	IV_4 = 9,
	PRK_exporter = 10,
	PRK_out_update = 11,
};

/**
 * @brief   Encodes the HKDF Info 
 * 
 * @param   label an in value indicating what kind of output we are generating
 * @param   context all possible contexts are listed in figure 7 in the spec
 * @param   context_len length of context
 * @param   okm_len the length of the output keying material
 * @param   out out-array
 * @param   out_len length of out
 * @return  err
 */
enum err create_hkdf_info(uint8_t label, uint8_t *context, uint32_t context_len,
			  uint32_t okm_len, uint8_t *out, uint32_t *out_len);

#endif
