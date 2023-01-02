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
	c->msg_len = sizeof(c->msg);
	c->th3_len = sizeof(c->th3);
	c->prk_3e2m_len = sizeof(c->prk_3e2m);
	c->th4_len = sizeof(c->th4);
	c->prk_4e3m_len = sizeof(c->prk_4e3m);
}
