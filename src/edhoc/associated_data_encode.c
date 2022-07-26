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
#include <string.h>

#include "edhoc/edhoc_cose.h"
#include "edhoc/associated_data_encode.h"

#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

enum err associated_data_encode(uint8_t *thX, const uint32_t thX_len,
				uint8_t *out, uint32_t *out_len)
{
	uint8_t context_str[] = { "Encrypt0" };
	return cose_enc_structure_encode(context_str,
					 (uint32_t)strlen((char *)context_str),
					 NULL, 0, thX, thX_len, out, out_len);
}
