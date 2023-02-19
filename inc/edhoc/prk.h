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
#include <stdbool.h>

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief                       Derives a pseudo random key (prk) form anther 
 *                              prk and static DH keys.
 * 
 * @param static_dh_auth        True if static DH keys should be used.
 * @param suite                 The cipher suite to be used.
 * @param label                 EDHOC-KDF label. 
 * @param[in] context           EDHOC-KDF context.
 * @param[in] prk_in            Input prk.
 * @param[in] stat_pk           Static public DH key. 
 * @param[in] stat_sk           Static secret DH key. 
 * @param[out] prk_out          The result.
 * @retval                      Ok or error code.
 */
enum err prk_derive(bool static_dh_auth, struct suite suite, uint8_t label,
		    struct byte_array *context, const struct byte_array *prk_in,
		    const struct byte_array *stat_pk,
		    const struct byte_array *stat_sk, uint8_t *prk_out);

#endif
