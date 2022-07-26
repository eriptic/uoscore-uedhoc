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

#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"

enum err check_buffer_size(uint32_t is_size, uint32_t required_size)
{
	if (is_size < required_size) {
		return buffer_to_small;
	} else {
		return ok;
	}
}

enum err _memcpy_s(uint8_t *dest, uint32_t dest_len, const uint8_t *source,
		   uint32_t source_len)
{
	if (source_len == 0) {
		return ok;
	}
	if ((NULL == dest) || (NULL == source)) {
		return wrong_parameter;
	}

	TRY(check_buffer_size(dest_len, source_len));
	memcpy(dest, source, source_len);
	return ok;
}
