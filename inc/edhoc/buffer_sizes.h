/*
 * Copyright (c) 2023 Eriptic Technologies
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#ifndef BUFFER_SIZES_H
#define BUFFER_SIZES_H

#ifndef EAD_SIZE
#define EAD_SIZE 0
#endif

#ifndef C_I_SIZE
#define C_I_SIZE 10
#endif

#ifndef C_R_SIZE
#define C_R_SIZE 10
#endif

#ifndef ID_CRED_I_SIZE
#define ID_CRED_I_SIZE 400
#endif

#ifndef ID_CRED_R_SIZE
#define ID_CRED_R_SIZE 400
#endif

#ifndef CRED_I_SIZE
#define CRED_I_SIZE 400
#endif

#ifndef CRED_R_SIZE
#define CRED_R_SIZE 400
#endif

#ifndef SUITES_I_SIZE
#define SUITES_I_SIZE 6
#endif

#define MAX(a, b) (((a) > (b)) ? (a) : (b))

#define BSTR_ENCODING_OVERHEAD(x)                                              \
	(((x) <= 5) ? 1 : ((x) <= UINT8_MAX) ? 2 : ((x) <= UINT16_MAX) ? 3 : 5)

#define AS_BSTR_SIZE(x) (BSTR_ENCODING_OVERHEAD(x) + x)

#define P_256_PRIV_KEY_SIZE 32
#define P_256_PUB_KEY_COMPRESSED_SIZE 33
#define P_256_PUB_KEY_UNCOMPRESSED_SIZE 65
#define P_256_PUB_KEY_X_CORD_SIZE 32
#define PK_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define G_Y_SIZE P_256_PUB_KEY_X_CORD_SIZE
#define G_X_SIZE P_256_PUB_KEY_X_CORD_SIZE
#define G_R_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define G_I_SIZE P_256_PUB_KEY_UNCOMPRESSED_SIZE
#define SIGNATURE_SIZE 64
#define ECDH_SECRET_SIZE 32
#define PRK_SIZE 32
#define HASH_SIZE 32
#define AEAD_IV_SIZE 13
#define MAC_SIZE 16
#define MAC23_SIZE 32
#define AAD_SIZE 45
#define KID_SIZE 8
#define SIG_OR_MAC_SIZE 64
#define COSE_SIGN1_STR_LEN 10 /* The length of the string "Signature1" */
#define COSE_ENC0_STR_LEN 8 /* The length of the string "Encrypt0"   */
#define CBOR_ENCODED_UINT 2
#define CBOR_ARRAY_4_ELEMENTS_OVERHEAD 1

#define PLAINTEXT2_SIZE                                                        \
	(AS_BSTR_SIZE(C_R_SIZE) + ID_CRED_I_SIZE +                             \
	 AS_BSTR_SIZE(SIG_OR_MAC_SIZE) + EAD_SIZE)
#define CIPHERTEXT2_SIZE PLAINTEXT2_SIZE
#define G_Y_CIPHERTEXT_2 (G_Y_SIZE + CIPHERTEXT2_SIZE)

#define PLAINTEXT3_SIZE                                                        \
	(ID_CRED_I_SIZE + AS_BSTR_SIZE(SIG_OR_MAC_SIZE) + EAD_SIZE)

#define CIPHERTEXT3_SIZE PLAINTEXT3_SIZE + MAC_SIZE

#define PLAINTEXT4_SIZE EAD_SIZE + COSE_ENC0_STR_LEN
#define CIPHERTEXT4_SIZE PLAINTEXT4_SIZE

#define MSG_1_SIZE                                                             \
	(1 + SUITES_I_SIZE + G_X_SIZE + AS_BSTR_SIZE(C_I_SIZE) + EAD_SIZE)
#define MSG_2_SIZE (G_Y_SIZE + CIPHERTEXT2_SIZE + AS_BSTR_SIZE(C_R_SIZE))

#define MSG_3_SIZE AS_BSTR_SIZE(CIPHERTEXT3_SIZE)
#define MSG_4_SIZE AS_BSTR_SIZE(CIPHERTEXT4_SIZE)

#define MSG12_MAX MAX(MSG_1_SIZE, MSG_2_SIZE)
#define MSG34_MAX MAX(MSG_3_SIZE, MSG_4_SIZE)
#define MSG_MAX_SIZE MAX(MSG12_MAX, MSG34_MAX)
#define PLAINTEXT23_MAX_SIZE MAX(PLAINTEXT2_SIZE, PLAINTEXT3_SIZE)
#define CRED_MAX_SIZE MAX(CRED_R_SIZE, CRED_I_SIZE)
#define ID_CRED_MAX_SIZE MAX(ID_CRED_R_SIZE, ID_CRED_I_SIZE)

#define SIG_STRUCT_SIZE_CALC(context, protected, external_aad, payload)        \
	AS_BSTR_SIZE(context) + AS_BSTR_SIZE(protected) +                      \
		AS_BSTR_SIZE(external_aad) + AS_BSTR_SIZE(payload) +           \
		CBOR_ARRAY_4_ELEMENTS_OVERHEAD

#define SIG_STRUCT_SIZE                                                        \
	SIG_STRUCT_SIZE_CALC(                                                  \
		COSE_SIGN1_STR_LEN, ID_CRED_MAX_SIZE,                          \
		(AS_BSTR_SIZE(HASH_SIZE) + CRED_MAX_SIZE + EAD_SIZE),          \
		MAC23_SIZE)


#define CONTEXT_MAC_SIZE                                                       \
	AS_BSTR_SIZE(AS_BSTR_SIZE(C_R_SIZE) + AS_BSTR_SIZE(HASH_SIZE) +        \
		     ID_CRED_MAX_SIZE + CRED_MAX_SIZE + EAD_SIZE)

#define INFO_MAX_SIZE CONTEXT_MAC_SIZE + 2 * CBOR_ENCODED_UINT

#define TH34_INPUT_SIZE                                                        \
	(AS_BSTR_SIZE(HASH_SIZE) + PLAINTEXT23_MAX_SIZE + CRED_MAX_SIZE)

#define TH2_INPUT_SIZE (AS_BSTR_SIZE(G_Y_SIZE) + AS_BSTR_SIZE(HASH_SIZE))

#endif
