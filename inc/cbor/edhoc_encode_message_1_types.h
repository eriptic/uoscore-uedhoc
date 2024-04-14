/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_ENCODE_MESSAGE_1_TYPES_H__
#define EDHOC_ENCODE_MESSAGE_1_TYPES_H__

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
	int32_t message_1_METHOD;
	union {
		struct {
			int32_t SUITES_I_suite_l_suite[10];
			size_t SUITES_I_suite_l_suite_count;
		};
		int32_t message_1_SUITES_I_int;
	};
	enum {
		SUITES_I_suite_l_c,
		message_1_SUITES_I_int_c,
	} message_1_SUITES_I_choice;
	struct zcbor_string message_1_G_X;
	union {
		int32_t message_1_C_I_int;
		struct zcbor_string message_1_C_I_bstr;
	};
	enum {
		message_1_C_I_int_c,
		message_1_C_I_bstr_c,
	} message_1_C_I_choice;
	struct zcbor_string message_1_ead_1;
	bool message_1_ead_1_present;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_ENCODE_MESSAGE_1_TYPES_H__ */
