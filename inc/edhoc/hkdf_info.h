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

/**
 * @brief   Encodes the HKDF Info 
 * 
 * @param   th transcripthash
 * @param   th_len length of th
 * @param   label human readable label
 * @param   context relevant only for MAC_2 and MAC_3
 * @param   context_len lenhgt of context
 * @param   okm_len the lenhgt of the output keying material
 * @param   out out-array
 * @param   out_len length of out
 * @return  err
 */
enum err create_hkdf_info(const uint8_t *th, uint32_t th_len, const char *label,
			  uint8_t *context, uint32_t context_len,
			  uint32_t okm_len, uint8_t *out, uint32_t *out_len);

#endif
