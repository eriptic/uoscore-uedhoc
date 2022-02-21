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
#include "c_x.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief   calculates transcript hash th2 
 * @param   alg hash algorithm to be used
 * @param   msg1 pointer to a message 1
 * @param   msg1_len length of message 1
 * @param   g_y Pointer to the public DH parameter
 * @param   c_r Pointer to the conception identifier of the responder
 * @param   th2 ouput buffer
 */
enum err th2_calculate(enum hash_alg alg, uint8_t *msg1, uint32_t msg1_len,
		       uint8_t *g_y, uint32_t g_y_len, struct c_x *c_r,
		       uint8_t *th2);

/**
 * @brief   calculates transcript hash th3
 * @param   alg hash algorithm to be used
 * @param   th2 pointer to a th2
 * @param   th2_len length of th2
 * @param   ciphertext_2 
 * @param   ciphertext_2_len  length of ciphertext_2_len
 * @param   th3 ouput buffer
 */
enum err th3_calculate(enum hash_alg alg, uint8_t *th2, uint32_t th2_len,
		       uint8_t *ciphertext_2, uint32_t ciphertext_2_len,
		       uint8_t *th3);

/**
 * @brief   calculates transcript hash th4
 * @param   alg hash algorithm to be used
 * @param   th3 pointer to a th3
 * @param   th3_len length of th3
 * @param   ciphertext_3
 * @param   ciphertext_3_len  length of ciphertext_3_len
 * @param   th4 ouput buffer
 */
enum err th4_calculate(enum hash_alg alg, uint8_t *th3, uint32_t th3_len,
		       uint8_t *ciphertext_3, uint32_t ciphertext_3_len,
		       uint8_t *th4);

#endif
