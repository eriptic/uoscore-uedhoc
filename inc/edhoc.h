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

/*define EDHOC_BUF_SIZES_RPK in order to use smaller buffers and save some RAM if need when RPKs are used*/
//#define EDHOC_BUF_SIZES_RPK
//#define EDHOC_BUF_SIZES_C509_CERT
#define EDHOC_BUF_SIZES_X509_CERT

#if defined EDHOC_BUF_SIZES_RPK
#define MSG_MAX_SIZE 100
#define CIPHERTEXT2_DEFAULT_SIZE 100
#define CIPHERTEXT3_DEFAULT_SIZE 100
#define A_2M_DEFAULT_SIZE 200
#define M_3_DEFAULT_SIZE 200
#define CRED_DEFAULT_SIZE 128
#define SGN_OR_MAC_DEFAULT_SIZE 128
#define ID_CRED_DEFAULT_SIZE 20
#define PRK_3AE_DEFAULT_SIZE 100
#define CERT_DEFAUT_SIZE 128
#define CONTEXT_MAC_DEFAULT_SIZE 200
#define INFO_DEFAULT_SIZE 250
#define SIGNATURE_STRUCT_DEFAULT_SIZE 300
#endif

#if defined EDHOC_BUF_SIZES_C509_CERT
#define MSG_MAX_SIZE 255
#define CIPHERTEXT2_DEFAULT_SIZE 255
#define CIPHERTEXT3_DEFAULT_SIZE 255
#define CIPHERTEXT4_DEFAULT_SIZE 255
#define A_2M_DEFAULT_SIZE 512
#define M_3_DEFAULT_SIZE 512
#define CRED_DEFAULT_SIZE 255
#define SGN_OR_MAC_DEFAULT_SIZE 128
#define ID_CRED_DEFAULT_SIZE 255
#define PLAINTEXT_DEFAULT_SIZE 255
#define CERT_DEFAUT_SIZE 255
#define CONTEXT_MAC_DEFAULT_SIZE 200
#define INFO_DEFAULT_SIZE 250
#define SIGNATURE_STRUCT_DEFAULT_SIZE 300
#endif

#if defined EDHOC_BUF_SIZES_X509_CERT
#define MSG_MAX_SIZE 700
#define PLAINTEXT_DEFAULT_SIZE 1580
#define CIPHERTEXT2_DEFAULT_SIZE PLAINTEXT_DEFAULT_SIZE
#define CIPHERTEXT3_DEFAULT_SIZE PLAINTEXT_DEFAULT_SIZE
#define CIPHERTEXT4_DEFAULT_SIZE PLAINTEXT_DEFAULT_SIZE
#define A_2M_DEFAULT_SIZE 512
#define M_3_DEFAULT_SIZE 512
#define CRED_DEFAULT_SIZE 600
#define SGN_OR_MAC_DEFAULT_SIZE 128
#define ID_CRED_DEFAULT_SIZE 600
#define CERT_DEFAULT_SIZE 600
#define CONTEXT_MAC_DEFAULT_SIZE 1580
#define INFO_DEFAULT_SIZE 1580
#define SIGNATURE_STRUCT_DEFAULT_SIZE 1580
#endif

#define SUITES_MAX 5
#define ERR_MSG_DEFAULT_SIZE 64
#define P_256_PRIV_KEY_DEFAULT_SIZE 32
#define P_256_PUB_KEY_COMPRESSED_SIZE 33
#define P_256_PUB_KEY_UNCOMPRESSED_SIZE 65
#define P_256_PUB_KEY_X_CORD_SIZE 32
#define PK_DEFAULT_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define C_R_DEFAULT_SIZE 16
#define C_I_DEFAULT_SIZE 16
#define G_Y_DEFAULT_SIZE P_256_PUB_KEY_X_CORD_SIZE
#define G_X_DEFAULT_SIZE P_256_PUB_KEY_X_CORD_SIZE
#define G_R_DEFAULT_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define G_I_DEFAULT_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define DATA_2_DEFAULT_SIZE                                                    \
	(C_I_DEFAULT_SIZE + G_Y_DEFAULT_SIZE + C_R_DEFAULT_SIZE)
#define TH2_INPUT_DEFAULT_SIZE                                                 \
	(G_Y_DEFAULT_SIZE + C_R_DEFAULT_SIZE + HASH_DEFAULT_SIZE)
#define TH34_INPUT_DEFAULT_SIZE                                                \
	(HASH_DEFAULT_SIZE + PLAINTEXT_DEFAULT_SIZE + CRED_DEFAULT_SIZE)
#define ECDH_SECRET_DEFAULT_SIZE 32
#define DERIVED_SECRET_DEFAULT_SIZE 32
#define AD_DEFAULT_SIZE 256
#define PRK_DEFAULT_SIZE 32
#define ASSOCIATED_DATA_DEFAULT_SIZE 64
#define KID_DEFAULT_SIZE 8
#define HASH_DEFAULT_SIZE 32
#define AEAD_KEY_DEFAULT_SIZE 16
#define MAC_DEFAULT_SIZE 16
#define AEAD_IV_DEFAULT_SIZE 13
#define SIGNATURE_DEFAULT_SIZE 64
#define TH_ENC_DEFAULT_SIZE 42
#define ENCODING_OVERHEAD 6

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
	struct byte_array ca; /*use only when authentication with certificates*/
	struct byte_array
		ca_pk; /*use only when authentication with certificates*/
};

struct edhoc_responder_context {
	bool msg4; /*if true massage 4 will be send by the responder*/
	struct byte_array c_r; /*connection identifier of the responder*/
	struct byte_array suites_r;
	struct byte_array g_y; /*ephemeral dh public key*/
	struct byte_array y; /*ephemeral dh secret key*/

	struct byte_array g_r; /* static DH pk -> use only with method 1 or 3*/
	struct byte_array r; /* static DH sk -> use only with method 1 or 3*/
	struct byte_array ead_2;
	struct byte_array ead_4;
	struct byte_array id_cred_r;
	struct byte_array cred_r;
	struct byte_array sk_r; /*sign key -use with method 0 and 2*/
	struct byte_array pk_r; /*coresp. pk to sk_r -use with method 0 and 2*/
	void *sock; /*pointer used as handler for sockets by tx/rx */
};

struct edhoc_initiator_context {
	bool msg4; /*if true massage 4 will be send by the responder*/
	struct byte_array c_i; /*connection identifier of the initiator*/
	enum method_type method;
	//uint8_t corr;
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
};

/**
 * @brief   Generates public and private ephemeral DH keys from a random seed. 
 *          
 *          IMPORTANT!!! PROVIDE A GOOD RANDOM SEED! 
 *
 * @param   curve DH curve to used
 * @param   seed a random seed
 * @param   sk pointer to a buffer where the secret key will be strored
 * @param   pk pointer to a buffer where the public key will be strored
 * @param   pk_size pointer to a variable with public key buffer size as input,
 *          and public key length as output.

 */
enum err WEAK ephemeral_dh_key_gen(enum ecdh_alg alg, uint32_t seed,
				   uint8_t *sk, uint8_t *pk, uint32_t *pk_size);

/**
 * @brief   Executes the EDHOC protocol on the initiator side
 * @param   c cointer to a structure containing initialization parameters
 * @param   cred_r_array containing elements of type other_party_cred used for
 *          the retrival of the other party (the responder) parameters at run
 *          time
 * @param   num_cred_r number of the elements in cred_r_array
 * @param   err_msg in case that an error message is received its contend is 
 *          provided to the caller though the err_msg
 * @param   ead_2 the received in msg2 additional data is provided to the 
 *          caller through ead_2
 * @param   ead_2_len length of ead_2
 * @param   prk_out the derived shared secret
 * @param   prk_out_len length of prk_out
 */
enum err edhoc_initiator_run(
	const struct edhoc_initiator_context *c,
	struct other_party_cred *cred_r_array, uint16_t num_cred_r,
	uint8_t *err_msg, uint32_t *err_msg_len, uint8_t *ead_2,
	uint32_t *ead_2_len, uint8_t *ead_4, uint32_t *ead_4_len,
	uint8_t *prk_out, uint32_t prk_out_len,
	enum err (*tx)(void *sock, uint8_t *data, uint32_t data_len),
	enum err (*rx)(void *sock, uint8_t *data, uint32_t *data_len));

/**
 * @brief   Executes the EDHOC protocol on the initiator side
 * @param   c cointer to a structure containing initialization parameters
 * @param   cred_r_array containing elements of type other_party_cred used for
 *          the retrival of the other party (the responder) parameters at run
 *          time
 * @param   num_cred_r number of the elements in cred_r_array
 * @param   err_msg in case that an error message is received its contend is 
 *          provided to the caller though the err_msg
 * @param   ead_2 the received in msg2 additional data is provided to the 
 *          caller through ead_2
 * @param   ead_2_len length of ead_2
 * @param   c_r_bytes connection identifier
 * @param   c_r_bytes_len length of c_i_bytes
 * @param   prk_out the derived shared secret
 * @param   prk_out_len length of prk_out
 */
enum err edhoc_initiator_run_extended(
	const struct edhoc_initiator_context *c,
	struct other_party_cred *cred_r_array, uint16_t num_cred_r,
	uint8_t *err_msg, uint32_t *err_msg_len, uint8_t *ead_2,
	uint32_t *ead_2_len, uint8_t *ead_4, uint32_t *ead_4_len,
	uint8_t *c_r_bytes, uint32_t *c_r_bytes_len, uint8_t *prk_out,
	uint32_t prk_out_len,
	enum err (*tx)(void *sock, uint8_t *data, uint32_t data_len),
	enum err (*rx)(void *sock, uint8_t *data, uint32_t *data_len));

/**
 * @brief   Executes the EDHOC protocol on the responder side
 * @param   c cointer to a structure containing initialization parameters
 * @param   cred_i_array containing elements of type other_party_cred used for 
 *          the retrival of the other party (the initiator) parameters at run 
 *          time
 * @param   num_cred_i number of the elements in cred_i_array
 * @param   err_msg in case that an error message is received its contend is 
 *          provided to the caller though the err_msg
 * @param   ead_1 the received in msg1 additional data is provided to the caller 
 *          through ead_1
 * @param   ead_1_len length of ead_1
 * @param   ead_3 the received in msg3 additional data is provided to the caller 
 *          through ead_3
 * @param   ead_3_len length of ead_3
 * @param   prk_out the derived shared secret
 * @param   prk_out_len length of prk_out
 */
enum err edhoc_responder_run(
	struct edhoc_responder_context *c,
	struct other_party_cred *cred_i_array, uint16_t num_cred_i,
	uint8_t *err_msg, uint32_t *err_msg_len, uint8_t *ead_1,
	uint32_t *ead_1_len, uint8_t *ead_3, uint32_t *ead_3_len,
	uint8_t *prk_out, uint32_t prk_out_len,
	enum err (*tx)(void *sock, uint8_t *data, uint32_t data_len),
	enum err (*rx)(void *sock, uint8_t *data, uint32_t *data_len));

/**
 * @brief   Executes the EDHOC protocol on the responder side
 * @param   c cointer to a structure containing initialization parameters
 * @param   cred_i_array containing elements of type other_party_cred used for
 *          the retrival of the other party (the initiator) parameters at run
 *          time
 * @param   num_cred_i number of the elements in cred_i_array
 * @param   err_msg in case that an error message is received its contend is
 *          provided to the caller though the err_msg
 * @param   ead_1 the received in msg1 additional data is provided to the caller
 *          through ead_1
 * @param   ead_1_len length of ead_1
 * @param   ead_3 the received in msg3 additional data is provided to the caller
 *          through ead_3
 * @param   ead_3_len length of ead_3
 * @param   prk_out the derived shared secret
 * @param   prk_out_len length of prk_out
 * @param   client_pub_key public key of the initiator
 * @param   client_pub_key_size length of client_pub_key
 * @param   c_i_bytes connection identifier
 * @param   c_i_bytes_len length of c_i_bytes
 */
enum err edhoc_responder_run_extended(
	struct edhoc_responder_context *c,
	struct other_party_cred *cred_i_array, uint16_t num_cred_i,
	uint8_t *err_msg, uint32_t *err_msg_len, uint8_t *ead_1,
	uint32_t *ead_1_len, uint8_t *ead_3, uint32_t *ead_3_len,
	uint8_t *prk_out, uint32_t prk_out_len, uint8_t *client_pub_key,
	uint32_t *client_pub_key_size, uint8_t *c_i_bytes,
	uint32_t *c_i_bytes_len,
	enum err (*tx)(void *sock, uint8_t *data, uint32_t data_len),
	enum err (*rx)(void *sock, uint8_t *data, uint32_t *data_len));

/**
 * @brief Computes PRK_exporter from PRK_out
 * 
 * @param app_hash_alg 	the EDHOC hash algorithm
 * @param prk_out 		the product of a successful EDHOC execution
 * @param prk_out_len 	length of prk_out
 * @param prk_exporter 	pointer where the prk_exporter value will be written
 * @return enum err 0 or error code
 */
enum err prk_out2exporter(enum hash_alg app_hash_alg, uint8_t *prk_out,
			  uint32_t prk_out_len, uint8_t *prk_exporter);

/**
 * @brief Updates PRK_out
 * 
 * @param app_hash_alg 	the EDHOC hash algorithm
 * @param prk_out 		the product of a successful EDHOC execution 
 * @param prk_out_len 	length of prk_out
 * @param context		A context on which initiator and responder needs to 
 * 						agree in front
 * @param context_len	length of context
 * @param prk_out_new 	pointer where the prk_out_new value will be written
 * @return enum err 0 or error code
 */
enum err prk_out_update(enum hash_alg app_hash_alg, uint8_t *prk_out,
			uint32_t prk_out_len, uint8_t *context,
			uint32_t context_len, uint8_t *prk_out_new);

enum export_label {
	OSCORE_MASTER_SECRET = 0,
	OSCORE_MASTER_SALT = 1,
};

/**
 * @brief 	Computes key material to be used within the application, 
 * 			e.g., OSCORE master secret or OSCORE master salt
 * 
 * @param app_hash_alg		the application hash algorithm
 * @param label				an uint value defined by the application 
 * @param prk_exporter		PRK computed with prk_out2exporter()
 * @param prk_exporter_len 	length of prk_exporter
 * @param out 				the result of the computation,
 * 							e.g., OSCORE master secret or OSCORE master salt
 * @param out_len 			length of out
 * @return enum err 		0 or error code
 */
enum err edhoc_exporter(enum hash_alg app_hash_alg, enum export_label label,
			uint8_t *prk_exporter, uint32_t prk_exporter_len,
			uint8_t *out, uint32_t out_len);

#endif
