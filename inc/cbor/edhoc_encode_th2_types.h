/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_ENCODE_TH2_TYPES_H__
#define EDHOC_ENCODE_TH2_TYPES_H__

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

struct th2 {
	struct zcbor_string th2_G_Y;
	union {
		struct zcbor_string th2_C_R_bstr;
		int32_t th2_C_R_int;
	};
	enum {
		th2_C_R_bstr_c,
		th2_C_R_int_c,
	} th2_C_R_choice;
	struct zcbor_string th2_hash_msg1;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_ENCODE_TH2_TYPES_H__ */
