/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <string.h>

#include "edhoc.h"

#include "edhoc/suites.h"
#include "edhoc/prk.h"
#include "edhoc/okm.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"

enum err prk_derive(bool static_dh_auth, struct suite suite, uint8_t label,
		    uint8_t *context, uint32_t context_len,
		    const uint8_t *prk_in, const uint32_t prk_in_len,
		    const uint8_t *stat_pk, const uint32_t stat_pk_len,
		    const uint8_t *stat_sk, const uint32_t stat_sk_len,
		    uint8_t *prk_out)
{
	if (static_dh_auth) {
		uint8_t dh_secret[ECDH_SECRET_DEFAULT_SIZE];

		TRY(shared_secret_derive(suite.edhoc_ecdh, stat_sk, stat_sk_len,
					 stat_pk, stat_pk_len, dh_secret));
		PRINT_ARRAY("dh_secret", dh_secret, sizeof(dh_secret));

		uint8_t salt[HASH_DEFAULT_SIZE];
		uint32_t salt_len = get_hash_len(suite.edhoc_hash);
		TRY(check_buffer_size(HASH_DEFAULT_SIZE, salt_len));

		TRY(edhoc_kdf(suite.edhoc_hash, prk_in, prk_in_len, label,
			      context, context_len, salt_len, salt));
		PRINT_ARRAY("SALT_3e2m or SALT4e3m", salt, salt_len);

		TRY(hkdf_extract(suite.edhoc_hash, salt, salt_len, dh_secret,
				 sizeof(dh_secret), prk_out));
	} else {
		/*it is save to do that since prks have the same size*/
		memcpy(prk_out, prk_in, prk_in_len);
	}
	return ok;
}
