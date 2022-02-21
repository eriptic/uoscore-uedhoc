/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef RUNTIME_CONTEXT_H
#define RUNTIME_CONTEXT_H

#include <stdint.h>

#include "edhoc.h"

struct runtime_context {
	uint8_t msg1[MSG_1_DEFAULT_SIZE];
	uint32_t msg1_len;
	uint8_t msg2[MSG_2_DEFAULT_SIZE];
	uint32_t msg2_len;
	uint8_t msg3[MSG_2_DEFAULT_SIZE];
	uint32_t msg3_len;
	uint8_t msg4[MSG_4_DEFAULT_SIZE];
	uint32_t msg4_len;
	struct suite suite;
	/*responder specific*/
	uint8_t th3[SHA_DEFAULT_SIZE];
	uint32_t th3_len;
	uint8_t PRK_3e2m[PRK_DEFAULT_SIZE];
	uint32_t PRK_3e2m_len;
	bool static_dh_i;
};



#endif
