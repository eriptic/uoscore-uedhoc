/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef PLAINTEXT_H
#define PLAINTEXT_H

#include <stdint.h>

#include "common/oscore_edhoc_error.h"

/**
 * @brief                       Decodes id_cred to kid.
 * 
 * @param[in] id_cred           ID_CRED_x
 * @param[out] kid              The result.
 * @retval                      Ok or error code.
 */
enum err id_cred2kid(const struct byte_array *id_cred, struct byte_array *kid);

/**
 * @brief                       Splits the plaintext of message 2. 
 *
 * @param[in] ptxt              Pointer to the plaintext.
 * @param[out] id_cred_x        ID_CRED_x.
 * @param[out] sign_or_mac      Signature or mac.
 * @param[out] ead              External Authorization Data.
 * @retval                      Ok or error code.
 */
enum err plaintext_split(struct byte_array *ptxt, struct byte_array *id_cred_x,
			 struct byte_array *sign_or_mac,
			 struct byte_array *ead);

#endif
