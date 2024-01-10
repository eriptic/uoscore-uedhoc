/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_ENCODE_INFO_TYPES_H__
#define EDHOC_ENCODE_INFO_TYPES_H__

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

struct info {
	uint32_t info_label;
	struct zcbor_string info_context;
	uint32_t info_length;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_ENCODE_INFO_TYPES_H__ */
