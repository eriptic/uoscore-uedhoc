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

#include "edhoc/buffer_sizes.h"

#include "edhoc/suites.h"
#include "edhoc/prk.h"
#include "edhoc/okm.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"

enum err prk_derive(bool static_dh_auth, struct suite suite, uint8_t label,
		    struct byte_array *context, const struct byte_array *prk_in,
		    const struct byte_array *stat_pk,
		    const struct byte_array *stat_sk, uint8_t *prk_out)
{
	if (static_dh_auth) {
		BYTE_ARRAY_NEW(dh_secret, ECDH_SECRET_SIZE, ECDH_SECRET_SIZE);

		TRY(shared_secret_derive(suite.edhoc_ecdh, stat_sk, stat_pk,
					 dh_secret.ptr));
		PRINT_ARRAY("dh_secret", dh_secret.ptr, dh_secret.len);

		BYTE_ARRAY_NEW(salt, HASH_SIZE, get_hash_len(suite.edhoc_hash));
		TRY(edhoc_kdf(suite.edhoc_hash, prk_in, label, context, &salt));
		PRINT_ARRAY("SALT_3e2m or SALT4e3m", salt.ptr, salt.len);

		TRY(hkdf_extract(suite.edhoc_hash, &salt, &dh_secret, prk_out));
	} else {
		/*it is save to do that since prks have the same size*/
		memcpy(prk_out, prk_in->ptr, prk_in->len);
	}
	return ok;
}
