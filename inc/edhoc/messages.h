/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef EDHOC_MESSAGES_H
#define EDHOC_MESSAGES_H

#include "common/byte_array.h"

struct msg_1 {
	uint8_t method_corr;
	struct byte_array suites_i;
	struct byte_array g_x;
	struct byte_array c_i;
	struct byte_array ead_1;
};

struct msg_2 {
	struct byte_array c_i;
	struct byte_array g_y;
	struct byte_array c_r;
	struct byte_array ciphertext;
};

struct error_msg {
	struct byte_array c_x;
	struct byte_array diag_msg;
	struct byte_array suites_r;
};

#endif
