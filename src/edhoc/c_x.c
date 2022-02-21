/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc/c_x.h"

#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"

void c_x_init(struct c_x *c, uint8_t *buf, uint32_t buf_len)
{
	byte_array_init(buf, buf_len, &c->mem.c_x_bstr);
}

enum err c_x_set(enum c_x_type t, const uint8_t *c_x_raw_buf,
		 uint32_t c_x_raw_buf_len, int c_x_int, struct c_x *out)
{
	if (t == INT) {
		out->type = INT;
		out->mem.c_x_int = c_x_int;
		return ok;
	} else {
		out->type = BSTR;
		out->mem.c_x_bstr.len = c_x_raw_buf_len;
		return _memcpy_s(out->mem.c_x_bstr.ptr, out->mem.c_x_bstr.len,
				 c_x_raw_buf, c_x_raw_buf_len);
	}
}

