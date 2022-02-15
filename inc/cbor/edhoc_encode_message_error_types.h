/*
 * Generated using zcbor version 0.3.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_ENCODE_MESSAGE_ERROR_TYPES_H__
#define EDHOC_ENCODE_MESSAGE_ERROR_TYPES_H__

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

struct message_error_C_x_ {
	union {
		struct zcbor_string _message_error_C_x_bstr;
		int32_t _message_error_C_x_int;
	};
	enum {
		_message_error_C_x_bstr,
		_message_error_C_x_int,
	} _message_error_C_x_choice;
};

struct message_error_SUITES_R_ {
	union {
		struct {
			int32_t _SUITES_R__supported_supported[10];
			uint_fast32_t _SUITES_R__supported_supported_count;
		};
		int32_t _message_error_SUITES_R_int;
	};
	enum {
		_SUITES_R__supported,
		_message_error_SUITES_R_int,
	} _message_error_SUITES_R_choice;
};

struct message_error {
	struct message_error_C_x_ _message_error_C_x;
	uint_fast32_t _message_error_C_x_present;
	struct zcbor_string _message_error_DIAG_MSG;
	struct message_error_SUITES_R_ _message_error_SUITES_R;
	uint_fast32_t _message_error_SUITES_R_present;
};


#endif /* EDHOC_ENCODE_MESSAGE_ERROR_TYPES_H__ */
