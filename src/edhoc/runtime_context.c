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
	c->msg1_len = sizeof(c->msg1);
	c->msg2_len = sizeof(c->msg2);
	c->msg3_len = sizeof(c->msg3);
	c->msg4_len = sizeof(c->msg4);
	c->th3_len = sizeof(c->th3);
	c->PRK_3e2m_len = sizeof(c->PRK_3e2m);
}
