/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef NONCE_H
#define NONCE_H

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief   Create the OSCORE nonce.
 * @param   id_piv "Sender ID of the endpoint that generated the Partial IV"
 * @param   piv MUST be max 5 bytes long
 * @param   common_iv MUST be 13 bytes long
 * @param   nonce MUST be 13 bytes long
 */
enum err create_nonce(struct byte_array *id_piv, struct byte_array *piv,
		      struct byte_array *common_iv, struct byte_array *nonce);

#endif
