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
#include "cbor/edhoc_encode_message_1.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_message_1(zcbor_state_t *state, const struct message_1 *input);


static bool encode_message_1(
		zcbor_state_t *state, const struct message_1 *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input).message_1_METHOD))))
	&& ((((*input).message_1_SUITES_I_choice == SUITES_I_suite_l_c) ? ((zcbor_list_start_encode(state, 10) && ((zcbor_multi_encode_minmax(2, 10, &(*input).SUITES_I_suite_l_suite_count, (zcbor_encoder_t *)zcbor_int32_encode, state, (&(*input).SUITES_I_suite_l_suite), sizeof(int32_t))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 10)))
	: (((*input).message_1_SUITES_I_choice == message_1_SUITES_I_int_c) ? ((zcbor_int32_encode(state, (&(*input).message_1_SUITES_I_int))))
	: false)))
	&& ((zcbor_bstr_encode(state, (&(*input).message_1_G_X))))
	&& ((((*input).message_1_C_I_choice == message_1_C_I_int_c) ? ((zcbor_int32_encode(state, (&(*input).message_1_C_I_int))))
	: (((*input).message_1_C_I_choice == message_1_C_I_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).message_1_C_I_bstr))))
	: false)))
	&& (!(*input).message_1_ead_1_present || zcbor_bstr_encode(state, (&(*input).message_1_ead_1))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_message_1(
		uint8_t *payload, size_t payload_len,
		const struct message_1 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_message_1, sizeof(states) / sizeof(zcbor_state_t), 5);
}
