/*
 * Generated using zcbor version 0.8.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef OSCORE_INFO_H__
#define OSCORE_INFO_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor/oscore_info_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


int cbor_encode_oscore_info(
		uint8_t *payload, size_t payload_len,
		const struct oscore_info *input,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* OSCORE_INFO_H__ */
