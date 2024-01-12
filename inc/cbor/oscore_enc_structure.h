/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef OSCORE_ENC_STRUCTURE_H__
#define OSCORE_ENC_STRUCTURE_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor/oscore_enc_structure_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


int cbor_encode_oscore_enc_structure(
		uint8_t *payload, size_t payload_len,
		const struct oscore_enc_structure *input,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* OSCORE_ENC_STRUCTURE_H__ */
