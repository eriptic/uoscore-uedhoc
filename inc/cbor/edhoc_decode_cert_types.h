/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_DECODE_CERT_TYPES_H__
#define EDHOC_DECODE_CERT_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <zcbor_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Which value for --default-max-qty this file was created with.
 *
 *  The define is used in the other generated file to do a build-time
 *  compatibility check.
 *
 *  See `zcbor --help` for more information about --default-max-qty
 */
#define DEFAULT_MAX_QTY 3

struct cert {
	int32_t _cert_type;
	int32_t _cert_serial_number;
	struct zcbor_string _cert_issuer;
	int32_t _cert_validity_not_before;
	int32_t _cert_validity_not_after;
	struct zcbor_string _cert_subject;
	int32_t _cert_subject_public_key_algorithm;
	struct zcbor_string _cert_pk;
	int32_t _cert_extensions;
	int32_t _cert_issuer_signature_algorithm;
	struct zcbor_string _cert_signature;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_DECODE_CERT_TYPES_H__ */
