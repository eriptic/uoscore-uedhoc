/*
   Copyright (c) 2022 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

/*
 * In the most general case the user of this library should use only the  
 * functions exposed in edhoc.h. Some more advance users may want to manage the 
 * edhoc state by themself. The functions in this file are meant to be used by 
 * such users. An example how the functions in this file can be used can be 
 * found in responder.c and initiator.c
 */

#ifndef EDHOC_INTERNAL_H
#define EDHOC_INTERNAL_H

#include <stdint.h>

#include "edhoc.h"
#include "edhoc/runtime_context.h"

#include "common/oscore_edhoc_error.h"

/**
 * @brief Initializes the EDHOC runtime context
 * 
 * @param c Pointer to the runtime context
 */
void runtime_context_init(struct runtime_context *c);

/**
 * @brief 			Generates message 1. 
 * 
 * @param[in] c 		Initiator context.
 * @param[in,out] rc 		Runtime context.
 * @retval			Ok or error code.
 */
enum err msg1_gen(const struct edhoc_initiator_context *c,
		  struct runtime_context *rc);

/**
 * @brief Generates message 3. This function should by used by on the 
 *        initiator side.
 * 
 * @param c initiator context
 * @param rc runtime context
 * @param cred_r_array array of CRED_Rs
 * @param num_cred_r Number of elements in CRED_R
 * @param ead_2 EAD_2 contained in message 2
 * @param ead_2_len length of EAD_2
 * @param prk_out the derived secret (output)
 * @param prk_out_len length of prk_4x3m
 * @return enum err 
 */
enum err msg3_gen(const struct edhoc_initiator_context *c,
		  struct runtime_context *rc, struct cred_array *cred_r_array,
		  struct byte_array *c_r, struct byte_array *prk_out);

/**
 * @brief Processes message 4. This function should by used by on the initiator 
 *        side. 
 * 
 * @param c initiator context
 * @param rc runtime context
 * @param ead_4 EAD_4 (output)
 * @param ead_4_len length of EAD_4
 * @return enum err 
 */
enum err msg4_process(struct runtime_context *rc);

/**
 * @brief 		Generates message 2. This function should by used by on the 
 * 				responder side.
 * 
 * @param 		c responder context
 * @param 		rc runtime context
 * @param[out] 	c_i_bytes connection identifier C_I
 * @return 		error code
 */
enum err msg2_gen(struct edhoc_responder_context *c, struct runtime_context *rc,
		  struct byte_array *c_i_bytes);

/**
 * @brief Processes message 3. This function should by used by on the responder 
 *        side. It produces prk_out to be used in the exporter interface.
 * 
 * @param c responder context
 * @param rc runtime context
 * @param cred_i_array Array of CRED_Is
 * @param num_cred_i Number of elements in cred_i_array
 * @param ead_3 EAD_3 from message 3 (output)
 * @param ead_3_len length of EAD_3
 * @param prk_out the derived secret (output)
 * @param prk_out_len length of prk_out
 * @param public_key public key of initiator
 * @param size of public key
 * @return enum err 
 */
enum err msg3_process(struct edhoc_responder_context *c,
		      struct runtime_context *rc,
		      struct cred_array *cred_i_array,
		      struct byte_array *prk_out,
		      struct byte_array *initiator_pk);

/**
 * @brief Generates message 4. This function should by used by on the responder 
 *        side.
 * 
 * @param c responder context
 * @param rc runtime context
 * @return enum err 
 */
enum err msg4_gen(struct edhoc_responder_context *c,
		  struct runtime_context *rc);
#endif
