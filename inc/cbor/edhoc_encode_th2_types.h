/*
 * Generated using zcbor version 0.3.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_ENCODE_TH2_TYPES_H__
#define EDHOC_ENCODE_TH2_TYPES_H__

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

struct th2 {
	struct zcbor_string _th2_hash_msg1;
	struct zcbor_string _th2_G_Y;
	union {
		struct zcbor_string _th2_C_R_bstr;
		int32_t _th2_C_R_int;
	};
	enum {
		_th2_C_R_bstr,
		_th2_C_R_int,
	} _th2_C_R_choice;
};


#endif /* EDHOC_ENCODE_TH2_TYPES_H__ */
