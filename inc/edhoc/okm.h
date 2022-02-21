/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef OKM_H
#define OKM_H

#include <stdint.h>

#include "hkdf_info.h"
#include "suites.h"

#include "common/oscore_edhoc_error.h"

/**
 * @brief   Derives output keying material.
 * 
 * @param   hash_alg HASH algorithm 
 * @param   prk pseudorandom key
 * @param   prk_len length of prk
 * @param   th transcripthash
 * @param   th_len length of th
 * @param   label human readable label
 * @param   context relevant only for MAC_2 and MAC_3
 * @param   context_len lenhgt of context
 * @param   okm ouput pointer
 * @param   okm_len length of okm
 */
enum err okm_calc(enum hash_alg hash_alg, const uint8_t *prk, uint32_t prk_len,
		  const uint8_t *th, uint32_t th_len, const char *label,
		  uint8_t *context, uint32_t context_len, uint8_t *okm,
		  uint32_t okm_len);

#endif
