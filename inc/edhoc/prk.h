/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef PRK_H
#define PRK_H

#include <stdint.h>

#include "common/oscore_edhoc_error.h"

/**
 * @brief   derives a pseudo random key (prk) form anther prk and static DH 
 *          keys.
 * @parma   static_dh_auth true if static DH keys should be used
 * @param   suite the ciphersuite used
 * @param   prk_in input prk
 * @param   prk_in_len length of prk_in
 * @param   stat_pk static public DH key 
 * @param   stat_pk_len length of stat_pk
 * @param   stat_sk static secret DH key 
 * @param   stat_sk_len length of stat_sk
 * @param   prk_out pointer to the buffer for the newly created PRK
 */
enum err prk_derive(bool static_dh_auth, struct suite suite,
		      const uint8_t *prk_in, const uint32_t prk_in_len,
		      const uint8_t *stat_pk, const uint32_t stat_pk_len,
		      const uint8_t *stat_sk, const uint32_t stat_sk_len,
		      uint8_t *prk_out);

#endif
