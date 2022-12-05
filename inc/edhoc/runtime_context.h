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
	uint8_t msg1_hash[HASH_DEFAULT_SIZE];
	uint8_t msg[MSG_MAX_SIZE];
	uint32_t msg_len;
	struct suite suite;
	/*initiator specific*/
	uint8_t th4[HASH_DEFAULT_SIZE];
	uint32_t th4_len;
	uint8_t prk_4e3m[PRK_DEFAULT_SIZE];
	uint32_t prk_4e3m_len;
	/*responder specific*/
	uint8_t th3[HASH_DEFAULT_SIZE];
	uint32_t th3_len;
	uint8_t prk_3e2m[PRK_DEFAULT_SIZE];
	uint32_t prk_3e2m_len;
	bool static_dh_i;
};

#endif
