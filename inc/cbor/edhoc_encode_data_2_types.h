/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_ENCODE_DATA_2_TYPES_H__
#define EDHOC_ENCODE_DATA_2_TYPES_H__

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

struct data_2_C_I_r {
	union {
		int32_t data_2_C_I_int;
		struct zcbor_string data_2_C_I_bstr;
	};
	enum {
		data_2_C_I_int_c,
		data_2_C_I_bstr_c,
	} data_2_C_I_choice;
};

struct data_2 {
	struct data_2_C_I_r data_2_C_I;
	bool data_2_C_I_present;
	struct zcbor_string data_2_G_Y;
	union {
		int32_t data_2_C_R_int;
		struct zcbor_string data_2_C_R_bstr;
	};
	enum {
		data_2_C_R_int_c,
		data_2_C_R_bstr_c,
	} data_2_C_R_choice;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_ENCODE_DATA_2_TYPES_H__ */
