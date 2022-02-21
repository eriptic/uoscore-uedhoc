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

enum err edhoc_exporter(enum hash_alg app_hash_alg,
				const uint8_t *prk_4x3m, uint32_t prk_4x3m_len,
				const uint8_t *th4, uint32_t th4_len,
				const char *label, uint8_t *out,
				uint32_t out_len)
{
	return okm_calc(app_hash_alg, prk_4x3m, prk_4x3m_len, th4, th4_len,
			label, NULL, 0, out, out_len);
}
