/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef SIGNATURE_OR_MAC_MSG_H
#define SIGNATURE_OR_MAC_MSG_H

#include <stdbool.h>

#include "suites.h"

#include "common/oscore_edhoc_error.h"

enum sgn_or_mac_op { VERIFY, GENERATE };

/**
 * @brief                        Computes or verify a signature or a mac.
 * 
 * @param op                     VERIFY or GENERATE
 * @param static_dh              True if static DH keys are used.
 * @param suite                  The cipher suite.
 * @param[in] sk                 Secret key.
 * @param[in] pk                 Public key. 
 * @param[in] prk                Pseudo random key used in key/iv generation. 
 * @param[in] th                 Transcript hash.
 * @param[in] id_cred            ID_CRED of the calling party.
 * @param[in] cred               CRED of the calling party.
 * @param[in] ead                External authorization data.
 * @param mac_label              MAC label, see specification.
 * @param[in,out] sig_or_mac     The computed signature or mac.
 * @return                       Ok or error. 
 */
enum err
signature_or_mac(enum sgn_or_mac_op op, bool static_dh, struct suite *suite,
		 const struct byte_array *sk, const struct byte_array *pk,
		 const struct byte_array *prk, const struct byte_array *th,
		 const struct byte_array *id_cred,
		 const struct byte_array *cred, const struct byte_array *ead,
		 enum info_label mac_label, struct byte_array *sig_or_mac);

#endif
