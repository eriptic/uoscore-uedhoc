/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc.h"

#include "edhoc/hkdf_info.h"
#include "edhoc/okm.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"

#include "common/print_util.h"

enum err edhoc_kdf(enum hash_alg hash_alg, const uint8_t *prk, uint32_t prk_len,
		   uint8_t label, uint8_t *context, uint32_t context_len,
		   uint32_t okm_len, uint8_t *okm)
{
	uint8_t info[INFO_DEFAULT_SIZE];
	uint32_t info_len = sizeof(info);

	TRY(create_hkdf_info(label, context, context_len, okm_len,
			     (uint8_t *)&info, &info_len));

	PRINT_ARRAY("info", info, info_len);
	return hkdf_expand(hash_alg, prk, prk_len, (uint8_t *)&info, info_len,
			   okm, okm_len);
}
