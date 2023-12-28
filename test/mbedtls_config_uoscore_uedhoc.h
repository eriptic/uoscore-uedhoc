/*
 * Copyright (c) 2023 Eriptic Technologies
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 * 
 * This is a custom mbedTLS configuration file that activates only required 
 * for OSCORE and EDHOC functionalities.
 */

//PSA crypto support
#define MBEDTLS_ENTROPY_HARDWARE_ALT
#define MBEDTLS_NO_PLATFORM_ENTROPY
#define MBEDTLS_ENTROPY_C
#define MBEDTLS_MD_C
#define MBEDTLS_HMAC_DRBG_C
#define MBEDTLS_PSA_CRYPTO_C

//AES support
#define MBEDTLS_CIPHER_C
#define MBEDTLS_AES_ROM_TABLES
#define MBEDTLS_AES_C
#define MBEDTLS_CCM_C

//X509 parsing support
#define MBEDTLS_PK_C /* MBEDTLS_X509_USE_C */
#define MBEDTLS_PK_PARSE_C /*required by MBEDTLS_X509_USE_C*/
#define MBEDTLS_OID_C /* required by MBEDTLS_X509_USE_C */
#define MBEDTLS_ASN1_PARSE_C /*required by MBEDTLS_ECDSA_C, MBEDTLS_PK_PARSE_C, MBEDTLS_X509_USE_C */
#define MBEDTLS_X509_USE_C /*required by MBEDTLS_X509_CRT_PARSE_C */
#define MBEDTLS_X509_CRT_PARSE_C

//SHA256 support
#define MBEDTLS_SHA224_C /*required by MBEDTLS_SHA256_C*/
#define MBEDTLS_SHA256_C

//ECDH, ECDSA and P256
#define MBEDTLS_ASN1_WRITE_C /*required by MBEDTLS_ECDSA_C*/
#define MBEDTLS_BIGNUM_C /*required by MBEDTLS_ECP_C, MBEDTLS_ECP_C*/
#define MBEDTLS_ECP_C /*required by MBEDTLS_ECDH_C, MBEDTLS_ECDH_C, MBEDTLS_PK_C */
#define MBEDTLS_ECDH_C
#define MBEDTLS_ECDSA_C
#define MBEDTLS_ECP_DP_SECP256R1_ENABLED
