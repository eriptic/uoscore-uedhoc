/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef OSCORE_INFO_TYPES_H__
#define OSCORE_INFO_TYPES_H__

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

struct oscore_info {
	struct zcbor_string _oscore_info_id;
	union {
		struct zcbor_string _oscore_info_id_context_bstr;
	};
	enum {
		_oscore_info_id_context_bstr,
		_oscore_info_id_context_nil,
	} _oscore_info_id_context_choice;
	union {
		int32_t _oscore_info_alg_aead_int;
		struct zcbor_string _oscore_info_alg_aead_tstr;
	};
	enum {
		_oscore_info_alg_aead_int,
		_oscore_info_alg_aead_tstr,
	} _oscore_info_alg_aead_choice;
	struct zcbor_string _oscore_info_type;
	uint32_t _oscore_info_L;
};

#ifdef __cplusplus
}
#endif

#endif /* OSCORE_INFO_TYPES_H__ */
