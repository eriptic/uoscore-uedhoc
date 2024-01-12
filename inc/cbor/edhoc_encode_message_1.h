/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_ENCODE_MESSAGE_1_H__
#define EDHOC_ENCODE_MESSAGE_1_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "cbor/edhoc_encode_message_1_types.h"

#ifdef __cplusplus
extern "C" {
#endif

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


int cbor_encode_message_1(
		uint8_t *payload, size_t payload_len,
		const struct message_1 *input,
		size_t *payload_len_out);


#ifdef __cplusplus
}
#endif

#endif /* EDHOC_ENCODE_MESSAGE_1_H__ */
