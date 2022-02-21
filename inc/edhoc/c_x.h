/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef C_X_H
#define C_X_H

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

enum c_x_type { INT, BSTR };

union c_x_mem {
	int c_x_int;
	struct byte_array c_x_bstr;
};

struct c_x {
	enum c_x_type type;
	union c_x_mem mem;
};

/**
 * @brief Initializes a c_x struct
 * 
 * @param c struct to be initialized
 * @param buf buffer containing the data
 * @param buf_len the lenhgt of the data
 */
void c_x_init(struct c_x *c, uint8_t *buf, uint32_t buf_len);

/**
 * @brief Sets a c_x struct
 * 
 * @param t Type of the C_x -- INT or BSTR
 * @param c_x_raw_buf raw C_x in case we have BSTR 
 * @param c_x_raw_buf_len lenhgt of c_x_raw_buf
 * @param c_x_int raw C_x in case we have INT 
 * @param out the output
 * @return enum err 
 */
enum err c_x_set(enum c_x_type t, const uint8_t *c_x_raw_buf,
		 uint32_t c_x_raw_buf_len, int c_x_int, struct c_x *out);

#endif
