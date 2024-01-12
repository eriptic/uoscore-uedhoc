/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "cbor/edhoc_encode_message_error.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_repeated_message_error_C_x(zcbor_state_t *state, const struct message_error_C_x_r *input);
static bool encode_repeated_message_error_SUITES_R(zcbor_state_t *state, const struct message_error_SUITES_R_r *input);
static bool encode_message_error(zcbor_state_t *state, const struct message_error *input);


static bool encode_repeated_message_error_C_x(
		zcbor_state_t *state, const struct message_error_C_x_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).message_error_C_x_choice == message_error_C_x_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).message_error_C_x_bstr))))
	: (((*input).message_error_C_x_choice == message_error_C_x_int_c) ? ((zcbor_int32_encode(state, (&(*input).message_error_C_x_int))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_message_error_SUITES_R(
		zcbor_state_t *state, const struct message_error_SUITES_R_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).message_error_SUITES_R_choice == SUITES_R_supported_l_c) ? ((zcbor_list_start_encode(state, 10) && ((zcbor_multi_encode_minmax(2, 10, &(*input).SUITES_R_supported_l_supported_count, (zcbor_encoder_t *)zcbor_int32_encode, state, (&(*input).SUITES_R_supported_l_supported), sizeof(int32_t))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 10)))
	: (((*input).message_error_SUITES_R_choice == message_error_SUITES_R_int_c) ? ((zcbor_int32_encode(state, (&(*input).message_error_SUITES_R_int))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_message_error(
		zcbor_state_t *state, const struct message_error *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((!(*input).message_error_C_x_present || encode_repeated_message_error_C_x(state, (&(*input).message_error_C_x)))
	&& ((zcbor_tstr_encode(state, (&(*input).message_error_DIAG_MSG))))
	&& (!(*input).message_error_SUITES_R_present || encode_repeated_message_error_SUITES_R(state, (&(*input).message_error_SUITES_R))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_message_error(
		uint8_t *payload, size_t payload_len,
		const struct message_error *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_message_error, sizeof(states) / sizeof(zcbor_state_t), 3);
}
