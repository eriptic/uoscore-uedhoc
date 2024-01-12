/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_DECODE_PLAINTEXT_H__
#define EDHOC_DECODE_PLAINTEXT_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor/edhoc_decode_plaintext_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


int cbor_decode_plaintext(
		const uint8_t *payload, size_t payload_len,
		struct plaintext *result,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* EDHOC_DECODE_PLAINTEXT_H__ */
