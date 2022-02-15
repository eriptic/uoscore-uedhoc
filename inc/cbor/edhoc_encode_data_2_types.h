/*
 * Generated using zcbor version 0.3.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_ENCODE_DATA_2_TYPES_H__
#define EDHOC_ENCODE_DATA_2_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"

/** Which value for --default-max-qty this file was created with.
 *
 *  The define is used in the other generated file to do a build-time
 *  compatibility check.
 *
 *  See `zcbor --help` for more information about --default-max-qty
 */
#define DEFAULT_MAX_QTY 3

struct data_2_C_I_ {
	union {
		int32_t _data_2_C_I_int;
		struct zcbor_string _data_2_C_I_bstr;
	};
	enum {
		_data_2_C_I_int,
		_data_2_C_I_bstr,
	} _data_2_C_I_choice;
};

struct data_2 {
	struct data_2_C_I_ _data_2_C_I;
	uint_fast32_t _data_2_C_I_present;
	struct zcbor_string _data_2_G_Y;
	union {
		int32_t _data_2_C_R_int;
		struct zcbor_string _data_2_C_R_bstr;
	};
	enum {
		_data_2_C_R_int,
		_data_2_C_R_bstr,
	} _data_2_C_R_choice;
};


#endif /* EDHOC_ENCODE_DATA_2_TYPES_H__ */
