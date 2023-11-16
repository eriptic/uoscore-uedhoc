/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdbool.h>

#include "edhoc/edhoc_method_type.h"

#include "common/oscore_edhoc_error.h"

void authentication_type_get(enum method_type m, volatile bool *static_dh_i,
			     volatile bool *static_dh_r)
{
	switch (m) {
	case INITIATOR_SK_RESPONDER_SK:
		*static_dh_i = false;
		*static_dh_r = false;
		break;
	case INITIATOR_SK_RESPONDER_SDHK:
		*static_dh_i = false;
		*static_dh_r = true;
		break;
	case INITIATOR_SDHK_RESPONDER_SK:
		*static_dh_i = true;
		*static_dh_r = false;
		break;
	case INITIATOR_SDHK_RESPONDER_SDHK:
		*static_dh_i = true;
		*static_dh_r = true;
	}
}
