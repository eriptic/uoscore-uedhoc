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
 * @brief   calculates transcript hash th2 
 * @param   alg hash algorithm to be used
 * @param   msg1_hash Message 1 hash
 * @param   g_y Pointer to the public DH parameter
 * @param   g_y_len length of g_y
 * @param   c_r Pointer to the conception identifier of the responder
 * @param   c_r_len length of c_r
 * @param   th2 ouput buffer
 */
enum err th2_calculate(enum hash_alg alg, uint8_t *msg1_hash,
		       uint8_t *g_y, uint32_t g_y_len, uint8_t *c_r,
		       uint32_t c_r_len, uint8_t *th2);

/**
 * @brief   calculates transcript hash th3. TH_3 = H(TH_2, PLAINTEXT_2) 
 * @param   alg hash algorithm to be used
 * @param   th2 pointer to a th2
 * @param   th2_len length of th2
 * @param   plaintext_2 plaintext 2
 * @param   plaintext_2_len length of plaintext_2
 * @param   cred_r cred_r
 * @param   cred_r_len length of cred_r
 * @param   th3 ouput buffer
 */
enum err th3_calculate(enum hash_alg alg, uint8_t *th2, uint32_t th2_len,
		       uint8_t *plaintext_2, uint32_t plaintext_2_len,
             uint8_t *cred_r, uint32_t cred_r_len,
		       uint8_t *th3);

/**
 * @brief   calculates transcript hash th4
 * @param   alg hash algorithm to be used
 * @param   th3 pointer to a th3
 * @param   th3_len length of th3
 * @param   plaintext_3 plaintext 3
 * @param   plaintext_3_len length of plaintext_3
 * @param   cred_i cred_i
 * @param   cred_i_len length of cred_i
 * @param   th4 ouput buffer
 */
enum err th4_calculate(enum hash_alg alg, uint8_t *th3, uint32_t th3_len,
		       uint8_t *plaintext_3, uint32_t plaintext_3_len,
             uint8_t *cred_i, uint32_t cred_i_len,
		       uint8_t *th4);

#endif
