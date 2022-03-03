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
#include "edhoc/c_x.h"

#include "common/oscore_edhoc_error.h"
#include "common/byte_array.h"
#include "common/print_util.h"

/*define EDHOC_BUF_SIZES_RPK in order to use smaller buffers and save some RAM if need when RPKs are used*/
//#define EDHOC_BUF_SIZES_RPK
//#define EDHOC_BUF_SIZES_C509_CERT
#define EDHOC_BUF_SIZES_X509_CERT

#if defined EDHOC_BUF_SIZES_RPK
#define MSG_1_DEFAULT_SIZE 64
#define MSG_2_DEFAULT_SIZE 128
#define MSG_3_DEFAULT_SIZE 100
#define MSG_4_DEFAULT_SIZE 100
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
#define MSG_1_DEFAULT_SIZE 255
#define MSG_2_DEFAULT_SIZE 255
#define MSG_3_DEFAULT_SIZE 255
#define MSG_4_DEFAULT_SIZE 255
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
#define MSG_1_DEFAULT_SIZE 255
#define MSG_2_DEFAULT_SIZE 700
#define MSG_3_DEFAULT_SIZE 700
#define MSG_4_DEFAULT_SIZE 700
#define PLAINTEXT_DEFAULT_SIZE 650
#define CIPHERTEXT2_DEFAULT_SIZE PLAINTEXT_DEFAULT_SIZE
#define CIPHERTEXT3_DEFAULT_SIZE PLAINTEXT_DEFAULT_SIZE
#define CIPHERTEXT4_DEFAULT_SIZE PLAINTEXT_DEFAULT_SIZE
#define A_2M_DEFAULT_SIZE 512
#define M_3_DEFAULT_SIZE 512
#define CRED_DEFAULT_SIZE 600
#define SGN_OR_MAC_DEFAULT_SIZE 128
#define ID_CRED_DEFAULT_SIZE 600
#define CERT_DEFAUT_SIZE 600
#define CONTEXT_MAC_DEFAULT_SIZE 1200
#define INFO_DEFAULT_SIZE 1200
#define SIGNATURE_STRUCT_DEFAULT_SIZE 1200
#endif

#define ERR_MSG_DEFAULT_SIZE 64
#define P_256_PRIV_KEY_DEFAULT_SIZE 32
#define P_256_PUB_KEY_COMPRESSED_SIZE 33
#define P_256_PUB_KEY_UNCOMPRESSED_SIZE 65
#define PK_DEFAULT_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define C_R_DEFAULT_SIZE 1
#define C_I_DEFAULT_SIZE 8
#define G_Y_DEFAULT_SIZE P_256_PUB_KEY_COMPRESSED_SIZE
#define G_X_DEFAULT_SIZE P_256_PUB_KEY_COMPRESSED_SIZE
#define G_R_DEFAULT_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define G_I_DEFAULT_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define DATA_2_DEFAULT_SIZE                                                    \
	(C_I_DEFAULT_SIZE + G_Y_DEFAULT_SIZE + C_R_DEFAULT_SIZE)
#define TH2_INPUT_DEFAULT_SIZE (MSG_1_DEFAULT_SIZE + DATA_2_DEFAULT_SIZE)
#define TH3_INPUT_DEFAULT_SIZE (SHA_DEFAULT_SIZE + CIPHERTEXT3_DEFAULT_SIZE)
#define TH4_INPUT_DEFAULT_SIZE (SHA_DEFAULT_SIZE + CIPHERTEXT4_DEFAULT_SIZE)
#define ECDH_SECRET_DEFAULT_SIZE 32
#define DERIVED_SECRET_DEFAULT_SIZE 32
#define AD_DEFAULT_SIZE 256
#define PRK_DEFAULT_SIZE 32
#define ASSOCIATED_DATA_DEFAULT_SIZE 64
#define KID_DEFAULT_SIZE 8
#define SHA_DEFAULT_SIZE 32
#define AEAD_KEY_DEFAULT_SIZE 16
#define MAC_DEFAULT_SIZE 16
#define AEAD_IV_DEFAULT_SIZE 13
#define SIGNATURE_DEFAULT_SIZE 64
#define TH_ENC_DEFAULT_SIZE 42
#define ENCODING_OVERHEAD 6



struct other_party_cred {
	struct byte_array id_cred; /*ID_CRED_x of the other party*/
	struct byte_array cred; /*CBOR encoded credentials*/
	struct byte_array pk; /*authentication pub key of the party */
	struct byte_array g; /*authentication static DH pub key of other party */
	struct byte_array ca; /*use only when authentication with certificates*/
	struct byte_array
		ca_pk; /*use only when authentication with certificates*/
};

struct edhoc_responder_context {
	bool msg4; /*if true massage 4 will be send by the responder*/
	struct c_x c_r; /*connection identifier of the responder*/
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
	struct c_x c_i; /*connection identifier of the initiator*/
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
enum err __attribute__((weak))
ephemeral_dh_key_gen(
	enum ecdh_alg alg, uint32_t seed, uint8_t *sk,
	uint8_t *pk, uint32_t *pk_size);

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
 * @param   prk_4x3m used in the exporter interface
 * @param   prk_4x3m_len length of prk_4x3m
 * @param   th4 transcript hash4 used in the exporter interface
 * @param   th4_len length of th4
 */
enum err edhoc_initiator_run(
	const struct edhoc_initiator_context *c,
	struct other_party_cred *cred_r_array, uint16_t num_cred_r,
	uint8_t *err_msg, uint32_t *err_msg_len, uint8_t *ead_2,
	uint32_t *ead_2_len, uint8_t *ead_4, uint32_t *ead_4_len,
	uint8_t *prk_4x3m, uint32_t prk_4x3m_len, uint8_t *th4,
	uint32_t th4_len,
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
 * @param   prk_4x3m used in the exporter interface
 * @param   prk_4x3m_len length of prk_4x3m
 * @param   th4 transcript hash4 used in the exporter interface
 * @param   th4_len length of th4
 */
enum err edhoc_responder_run(
	struct edhoc_responder_context *c,
	struct other_party_cred *cred_i_array, uint16_t num_cred_i,
	uint8_t *err_msg, uint32_t *err_msg_len, uint8_t *ead_1,
	uint32_t *ead_1_len, uint8_t *ead_3, uint32_t *ead_3_len,
	uint8_t *prk_4x3m, uint32_t prk_4x3m_len, uint8_t *th4,
	uint32_t th4_len,
	enum err (*tx)(void *sock, uint8_t *data, uint32_t data_len),
	enum err (*rx)(void *sock, uint8_t *data, uint32_t *data_len));

/**
 * @brief   used to create application specific symmetric keys using the 
 *          calculated in edhoc_initiator_run()/edhoc_responder_run() prk_4x3m
 *          and th4
 * @param   app_hash_alg hash algorithm to be used in the derivation
 * @param   app_aead_alg AEAD algorithm to be used in the derivation
 * @param   prk_4x3m derived key  
 * @param   prk_4x3m_len length of prk_4x3m
 * @param   th4 transcripthash see edhoc_initiator_run()/edhoc_responder_run()
 * @param   th4_len length of th4
 * @param   label a human readble string idicating the key purpose
 * @param   out container for the derivide key
 * @param   out_len length of the derived key
 */
enum err edhoc_exporter(enum hash_alg app_hash_alg, const uint8_t *prk_4x3m,
			uint32_t prk_4x3m_len, const uint8_t *th4,
			uint32_t th4_len, const char *label, uint8_t *out,
			uint32_t out_len);
#endif
