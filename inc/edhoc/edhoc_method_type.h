/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef EDHOC_METHOD_TYPE_H
#define EDHOC_METHOD_TYPE_H

#include <stdbool.h>

#include "common/oscore_edhoc_error.h"

/*
+-------+-------------------+-------------------+-------------------+
| Value | Initiator         | Responder         | Reference         |
+-------+-------------------+-------------------+-------------------+
|     0 | Signature Key     | Signature Key     | [1]               |
|     1 | Signature Key     | Static DH Key     | [1]               |
|     2 | Static DH Key     | Signature Key     | [1]               |
|     3 | Static DH Key     | Static DH Key     | [1]               |
+-------+-------------------+-------------------+-------------------+
[1]: https://datatracker.ietf.org/doc/draft-ietf-lake-edhoc/
*/

enum method_type {
	INITIATOR_SK_RESPONDER_SK = 0,
	INITIATOR_SK_RESPONDER_SDHK = 1,
	INITIATOR_SDHK_RESPONDER_SK = 2,
	INITIATOR_SDHK_RESPONDER_SDHK = 3,
};

/**
 * @brief                       Retrieves the authentication type of initiator 
 *                              and responder.
 * 
 * @param m                     The method.
 * @param[out] static_dh_i      True if the initiator authenticates with static 
 *                              DH key.
 * @param[out] static_dh_r      True if the responder authenticates with static 
 *                              DH key.
 * @retval                      None.
 */
void authentication_type_get(enum method_type m, volatile bool *static_dh_i,
				 volatile bool *static_dh_r);

#endif
