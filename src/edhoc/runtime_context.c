/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <string.h>

#include "edhoc_internal.h"

#include "edhoc/runtime_context.h"

void runtime_context_init(struct runtime_context *c)
{
	c->msg.len = sizeof(c->msg_buf);
	c->msg.ptr = c->msg_buf;

#if EAD_SIZE != 0
	c->ead.len = sizeof(c->ead_buf);
	c->ead.ptr = c->ead_buf;
#else
	c->ead.len = 0;
	c->ead.ptr = NULL;
#endif
	c->msg1_hash.ptr = c->msg1_hash_buf;
	c->msg1_hash.len = sizeof(c->msg1_hash_buf);

	c->th3.ptr = c->th3_buf;
	c->th3.len = sizeof(c->th3_buf);
	c->prk_3e2m.ptr = c->prk_3e2m_buf;
	c->prk_3e2m.len = sizeof(c->prk_3e2m_buf);

	c->th4.ptr = c->th4_buf;
	c->th4.len = sizeof(c->th4_buf);
	c->prk_4e3m.ptr = c->prk_4e3m_buf;
	c->prk_4e3m.len = sizeof(c->prk_4e3m_buf);
}
