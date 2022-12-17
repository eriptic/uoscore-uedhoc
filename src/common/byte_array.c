/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "common/byte_array.h"
#include "common/memcpy_s.h"
#include "common/oscore_edhoc_error.h"

uint8_t EMPTY_STRING[] = { "" };
struct byte_array EMPTY_ARRAY = {
	.len = 0,
	.ptr = EMPTY_STRING,
};

struct byte_array NULL_ARRAY = {
	.len = 0,
	.ptr = NULL,
};

enum err byte_array_cpy(struct byte_array *dest, const struct byte_array *src,
			const uint32_t dest_max_len)
{
	TRY(_memcpy_s(dest->ptr, dest_max_len, src->ptr, src->len));
	dest->len = src->len;
	return ok;
}

bool array_equals(const struct byte_array *left, const struct byte_array *right)
{
	if (left->len != right->len) {
		return false;
	}
	for (uint32_t i = 0; i < left->len; i++) {
		if (left->ptr[i] != right->ptr[i]) {
			return false;
		}
	}
	return true;
}
