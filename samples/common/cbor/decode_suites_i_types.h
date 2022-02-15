/*
 * Generated using zcbor version 0.3.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef DECODE_SUITES_I_TYPES_H__
#define DECODE_SUITES_I_TYPES_H__

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

struct suites_ {
	union {
		struct {
			int32_t _suites__int_int[3];
			uint_fast32_t _suites__int_int_count;
		};
		int32_t _suites_int;
	};
	enum {
		_suites__int,
		_suites_int,
	} _suites_choice;
};


#endif /* DECODE_SUITES_I_TYPES_H__ */
