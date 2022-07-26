/*
 * Generated using zcbor version 0.3.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef OSCORE_AAD_ARRAY_H__
#define OSCORE_AAD_ARRAY_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "cbor/oscore_aad_array_types.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


bool cbor_encode_aad_array(
		uint8_t *payload, size_t payload_len,
		const struct aad_array *input,
		size_t *payload_len_out);


#endif /* OSCORE_AAD_ARRAY_H__ */
