/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef TH_H
#define TH_H

#include "suites.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief                       Calculates transcript hash th2. 
 * 
 * @param alg                   Hash algorithm to be used.
 * @param[in] msg1_hash         Hash of Message 1.
 * @param[in] g_y               Public DH parameter.
 * @param[in] c_r               Connection identifier of the responder.
 * @param[out] th2              The result.
 * @retval                      Ok or error.
 */
enum err th2_calculate(enum hash_alg alg, struct byte_array *msg1_hash,
		       struct byte_array *g_y, struct byte_array *c_r,
		       struct byte_array *th2);

/**
 * @brief                       Calculates transcript hash th3/th4 
 *                              TH_3 = H(TH_2, PLAINTEXT_2) 
 *                              TH_4 = H(TH_3, PLAINTEXT_3) 
 * 
 * @param alg                   Hash algorithm to be used.
 * @param[in] th23              th2 ot th3.
 * @param[in] plaintext_23      Plaintext 2 or plaintext 3.
 * @param[in] cred              The credential.
 * @param[out] th34             The result.
 */
enum err th34_calculate(enum hash_alg alg, struct byte_array *th23,
			struct byte_array *plaintext_23,
			const struct byte_array *cred, struct byte_array *th34);

#endif
