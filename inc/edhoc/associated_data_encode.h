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
 * @brief                       Encodes associated data for message 3. 
 *                              (COSE "Encrypt0") data structure is used.
 * 
 * @param[in] th                Can be th2 or th3.
 * @param[out] out              The encoded data.
 * @retval                      Ok or error code.
 */
enum err associated_data_encode(struct byte_array *thX, struct byte_array *out);

#endif
