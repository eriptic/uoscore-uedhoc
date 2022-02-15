/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef A_3AE_ENCODE_H
#define A_3AE_ENCODE_H

#include <stdint.h>

#include "common/oscore_edhoc_error.h"

/**
 * @brief   Ecodes associated data for message 3. (COSE "Encrypt0") data 
 *          structure is used 
 * @param   th can be th2 or th3
 * @param   th_len the length of th
 * @param   out pointer to hold the encoded data
 * @param   out_len length of the encoded data
 */
enum err associated_data_encode(uint8_t *th, const uint32_t th_len,
				uint8_t *out, uint32_t *out_len);

#endif
