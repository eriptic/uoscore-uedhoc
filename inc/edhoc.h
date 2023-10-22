/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef EDHOC_H
#define EDHOC_H

#include <stdint.h>

#include "edhoc/edhoc_method_type.h"
#include "edhoc/messages.h"
#include "edhoc/suites.h"
#include "edhoc/hkdf_info.h"

#include "common/oscore_edhoc_error.h"
#include "common/byte_array.h"
#include "common/print_util.h"

#ifdef _WIN32
#define WEAK
#else
#define WEAK __attribute__((weak))
#endif

struct other_party_cred {
	struct byte_array id_cred; /*ID_CRED_x of the other party*/
	struct byte_array cred; /*CBOR encoded credentials*/
	struct byte_array pk; /*authentication pub key of the other party */
	struct byte_array g; /*authentication static DH pub key of other party */
	struct byte_array ca; /*use only when certificates are used*/
	struct byte_array ca_pk; /*use only when certificates are used*/
};

struct cred_array {
	uint32_t len;
	struct other_party_cred *ptr;
};

struct edhoc_responder_context {
	struct byte_array c_r; /*connection identifier of the responder*/
	struct byte_array suites_r;
	struct byte_array g_y; /*ephemeral dh public key*/
	struct byte_array y; /*ephemeral dh secret key*/
	struct byte_array g_r; /* static DH pk -> use only with method 1 or 3*/
	struct byte_array r; /* static DH sk -> use only with method 1 or 3*/
	struct byte_array ead_2; /*EAD to be send in message 2*/
	struct byte_array ead_4; /*EAD to be send in message 4*/
	struct byte_array id_cred_r;
	struct byte_array cred_r;
	struct byte_array sk_r; /*sign key -use with method 0 and 2*/
	struct byte_array pk_r; /*coresp. pk to sk_r -use with method 0 and 2*/
	void *sock; /*pointer used as handler for sockets by tx/rx */
	void *params_ead_process; /*parameters for processing EAD1 and EAD3 */
};

struct edhoc_initiator_context {
	struct byte_array c_i; /*connection identifier of the initiator*/
	enum method_type method;
	struct byte_array suites_i;
	struct byte_array ead_1;
	struct byte_array ead_3;
	struct byte_array id_cred_i;
	struct byte_array cred_i;
	struct byte_array g_x; /*ephemeral dh public key*/
	struct byte_array x; /*ephemeral dh secret key*/
	struct byte_array g_i; /* static DH pk -> use only with method 2 or 3*/
	struct byte_array i; /* static DH sk -> use only with method 2 or 3*/
	struct byte_array sk_i; /*sign key use with method 0 and 2*/
	struct byte_array pk_i; /*coresp. pk to sk_r -use with method 0 and 2*/
	void *sock; /*pointer used as handler for sockets by tx/rx */
	void *params_ead_process; /*parameters for processing EAD2 and EAD4 */
};

/**
 * @brief   			Generates ephemeral DH keys from a random seed. 
 *			
 *				!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *          			IMPORTANT!!! PROVIDE A GOOD RANDOM SEED! 
 *				!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
 *
 * @param alg			The ECDH algorithm to be used.
 * @param seed			A random seed.
 * @param[out] sk 		The newly generated private key.
 * @param[out] pk 		The newly private private key.
 * @return 			Ok or error code.
 */
enum err WEAK ephemeral_dh_key_gen(enum ecdh_alg alg, uint32_t seed,
				   struct byte_array *sk,
				   struct byte_array *pk);

/**
 * @brief   			Executes EDHOC on the initiator side.
 * 
 * @param[in] c 		Initialization parameters.
 * @param[in] cred_r_array 	Trust anchors for authenticating the responder.
 * @param[out] err_msg 		A buffer for an error message.
 * @param[out] prk_out 		The derived shared secret.
 * @param tx			A callback function for sending messages.
 * @param rx			A callback function for receiving messages.
 * @param ead_process		A callback function for processing EAD.
 * @return 			Ok or error code.
 */
enum err edhoc_initiator_run(
	const struct edhoc_initiator_context *c,
	struct cred_array *cred_r_array, struct byte_array *err_msg,
	struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead24));

/**
 * @brief 			Executes EDHOC on the initiator side and 
 * 				provides access to the received C_R
 * 
 * @param[in] c 		Initialization parameters.
 * @param[in] cred_r_array 	Trust anchors for authenticating the responder.
 * @param[out] err_msg 		A buffer for an error message.
 * @param[out] c_r_bytes 	Connection identifier of requester.
 * @param[out] prk_out 		The derived shared secret.
 * @param tx			A callback function for sending messages.
 * @param rx			A callback function for receiving messages.
 * @param ead_process		A callback function for processing EAD.
 * @return 			Ok or error code.
 */
enum err edhoc_initiator_run_extended(
	const struct edhoc_initiator_context *c,
	struct cred_array *cred_r_array, struct byte_array *err_msg,
	struct byte_array *c_r_bytes, struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead24));

/**
 * @brief			Executes EDHOC on the responder side.
 * 
 * @param[in] c 		Initialization parameters.
 * @param[in] cred_i_array 	Trust anchors for authenticating the initiator.
 * @param[out] err_msg 		A buffer for an error message.
 * @param[out] prk_out 		The derived shared secret. 
 * @param tx			A callback function for sending messages.
 * @param rx			A callback function for receiving messages.
 * @param ead_process		A callback function for processing EAD.
 * @return 			Ok or error code.
 */
enum err edhoc_responder_run(
	struct edhoc_responder_context *c, struct cred_array *cred_i_array,
	struct byte_array *err_msg, struct byte_array *prk_out,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead13));

/**
 * @brief			Executes EDHOC on the responder side and
 * 				provides access to the received C_I
 * 
 * @param[in] c 		Initialization parameters.
 * @param[in] cred_i_array 	Trust anchors for authenticating the initiator.
 * @param[out] err_msg 		A buffer for an error message.
 * @param[out] prk_out 		The derived shared secret. 
 * @param[out] initiator_pk 	Public key of the initiator.
 * @param[out] c_i_bytes 	Connection identifier of the initiator.
 * @param tx			A callback function for sending messages.
 * @param rx			A callback function for receiving messages.
 * @param ead_process		A callback function for processing EAD.
 * @return 			Ok or error code.
 */
enum err edhoc_responder_run_extended(
	struct edhoc_responder_context *c, struct cred_array *cred_i_array,
	struct byte_array *err_msg, struct byte_array *prk_out,
	struct byte_array *initiator_pk, struct byte_array *c_i_bytes,
	enum err (*tx)(void *sock, struct byte_array *data),
	enum err (*rx)(void *sock, struct byte_array *data),
	enum err (*ead_process)(void *params, struct byte_array *ead13));

/**
 * @brief 			Computes PRK_exporter from PRK_out.
 * 
 * @param app_hash_alg 		The EDHOC hash algorithm.
 * @param[in] prk_out 		The product of a successful EDHOC execution.
 * @param[out] prk_exporter 	The result.
 * @return 			Ok or error code.
 */
enum err prk_out2exporter(enum hash_alg app_hash_alg,
			  struct byte_array *prk_out,
			  struct byte_array *prk_exporter);

/**
 * @brief 			Updates PRK_out.
 * 
 * @param app_hash_alg 		The EDHOC hash algorithm.
 * @param[in] prk_out 		The product of a successful EDHOC execution. 
 * @param[in] context		A common context known by initiator & responder. 
 * @param[out] prk_out_new 	The new prk_out value.
 * @return 			Ok or error code.
 */
enum err prk_out_update(enum hash_alg app_hash_alg, struct byte_array *prk_out,
			struct byte_array *context,
			struct byte_array *prk_out_new);

enum export_label {
	OSCORE_MASTER_SECRET = 0,
	OSCORE_MASTER_SALT = 1,
};

/**
 * @brief 			Computes key material to be used within the 
 * 				application, e.g., OSCORE master secret or 
 * 				OSCORE master salt.
 * 
 * @param app_hash_alg 		The application hash algorithm.
 * @param label 		An uint value defined by the application. 
 * @param[in] prk_exporter 	PRK computed with prk_out2exporter().
 * @param[out] out 		The result of the computation, e.g., OSCORE 
 * 				master secret or OSCORE master salt.
 * @return			Ok or error code.
 */
enum err edhoc_exporter(enum hash_alg app_hash_alg, enum export_label label,
			struct byte_array *prk_exporter,
			struct byte_array *out);

#endif
