/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdint.h>

#include "edhoc.h"

#include "edhoc/hkdf_info.h"
#include "edhoc/okm.h"
#include "edhoc/suites.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"

enum err prk_out2exporter(enum hash_alg app_hash_alg, uint8_t *prk_out,
			  uint32_t prk_out_len, uint8_t *prk_exporter)
{
	return edhoc_kdf(app_hash_alg, prk_out, prk_out_len, PRK_exporter, NULL,
			 0, get_hash_len(app_hash_alg), prk_exporter);
}

enum err prk_out_update(enum hash_alg app_hash_alg, uint8_t *prk_out,
			uint32_t prk_out_len, uint8_t *context,
			uint32_t context_len, uint8_t *prk_out_new)
{
	return edhoc_kdf(app_hash_alg, prk_out, prk_out_len, PRK_out_update,
			 context, context_len, get_hash_len(app_hash_alg),
			 prk_out_new);
}

enum err edhoc_exporter(enum hash_alg app_hash_alg, enum export_label label,
			uint8_t *prk_exporter, uint32_t prk_exporter_len,
			uint8_t *out, uint32_t out_len)
{
	return edhoc_kdf(app_hash_alg, prk_exporter, prk_exporter_len, label,
			 NULL, 0, out_len, out);
}