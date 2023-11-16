/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_DECODE_MESSAGE_1_TYPES_H__
#define EDHOC_DECODE_MESSAGE_1_TYPES_H__

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

struct message_1 {
	int32_t _message_1_METHOD;
	union {
		struct {
			int32_t _SUITES_I__suite_suite[10];
			size_t _SUITES_I__suite_suite_count;
		};
		int32_t _message_1_SUITES_I_int;
	};
	enum {
		_SUITES_I__suite,
		_message_1_SUITES_I_int,
	} _message_1_SUITES_I_choice;
	struct zcbor_string _message_1_G_X;
	union {
		int32_t _message_1_C_I_int;
		struct zcbor_string _message_1_C_I_bstr;
	};
	enum {
		_message_1_C_I_int,
		_message_1_C_I_bstr,
	} _message_1_C_I_choice;
	struct zcbor_string _message_1_ead_1;
	bool _message_1_ead_1_present;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_DECODE_MESSAGE_1_TYPES_H__ */
