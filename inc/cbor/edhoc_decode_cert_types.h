/*
 * Generated using zcbor version 0.3.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_DECODE_CERT_TYPES_H__
#define EDHOC_DECODE_CERT_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"

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


#endif /* EDHOC_DECODE_CERT_TYPES_H__ */
