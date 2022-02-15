/*
 * Generated using zcbor version 0.3.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef DECODE_C_X_TYPES_H__
#define DECODE_C_X_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"

/** Which value for --default-max-qty this file was created with.
 *
 *  The define is used in the other generated file to do a build-time
 *  compatibility check.
 *
 *  See `zcbor --help` for more information about --default-max-qty
 */
#define DEFAULT_MAX_QTY 3

struct cx_C_X_ {
	union {
		struct zcbor_string _cx_C_X_bstr;
		int32_t _cx_C_X_int;
	};
	enum {
		_cx_C_X_bstr,
		_cx_C_X_int,
	} _cx_C_X_choice;
};


#endif /* DECODE_C_X_TYPES_H__ */
