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
 * @brief   Decodes id_cred to kid
 * @param   id_cred ID_CRED_x
 * @param   id_cred_len length of id_cred
 * @param   _kid output pointer
 * @param   kid_len length of the kid
 */
enum err id_cred2kid(const struct byte_array *id_cred, struct byte_array *kid);

/**
 * @brief   Splits a the plaintext of message 2 to its subfields
 * @param   ptxt pointer to the plaintext
 * @param   ptxt_len length of ptxt
 * @param   id_cred_x ID_CRED_x
 * @param   id_cred_x_len length of id_cred_x_len
 * @param   sign_or_mac signature or mac
 * @param   sign_or_mac_len length of sign_or_mac
 * @param   ad axillary data
 * @param   ad_len length of ad
 */
enum err plaintext_split(struct byte_array *ptxt, struct byte_array *id_cred_x,
			 struct byte_array *sign_or_mac, struct byte_array *ad);

#endif
