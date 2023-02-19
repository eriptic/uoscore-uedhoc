/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/buffer_sizes.h"

#include "edhoc/hkdf_info.h"
#include "edhoc/okm.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"

#include "common/print_util.h"

enum err edhoc_kdf(enum hash_alg hash_alg, const struct byte_array *prk,
		   uint8_t label, struct byte_array *context,
		   struct byte_array *okm)
{
	PRINTF("INFO_MAX_SIZE: %d\n", INFO_MAX_SIZE);
	PRINTF("context->len: %d\n", context->len);
	BYTE_ARRAY_NEW(info, INFO_MAX_SIZE, context->len + ENCODING_OVERHEAD);

	TRY(create_hkdf_info(label, context, okm->len, &info));

	PRINT_ARRAY("info", info.ptr, info.len);
	return hkdf_expand(hash_alg, prk, &info, okm);
}
