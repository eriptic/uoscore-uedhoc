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

#include "common/byte_array.h"
#include "edhoc/buffer_sizes.h"
#include "edhoc/suites.h"

struct runtime_context {
	uint8_t msg_buf[MSG_MAX_SIZE];
	struct byte_array msg;
#if EAD_SIZE != 0
	uint8_t ead_buf[EAD_SIZE];
#endif
	struct byte_array ead;
	struct suite suite;
	uint8_t msg1_hash_buf[HASH_SIZE];
	struct byte_array msg1_hash;

	/*initiator specific*/
	uint8_t th4_buf[HASH_SIZE];
	struct byte_array th4;
	uint8_t prk_4e3m_buf[PRK_SIZE];
	struct byte_array prk_4e3m;

	/*responder specific*/
	bool static_dh_i;
	uint8_t th3_buf[HASH_SIZE];
	struct byte_array th3;
	uint8_t prk_3e2m_buf[PRK_SIZE];
	struct byte_array prk_3e2m;
};

#endif
