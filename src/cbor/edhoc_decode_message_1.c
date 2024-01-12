/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "cbor/edhoc_decode_message_1.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_message_1(zcbor_state_t *state, struct message_1 *result);


static bool decode_message_1(
		zcbor_state_t *state, struct message_1 *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result).message_1_METHOD))))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_list_start_decode(state) && ((zcbor_multi_decode(2, 10, &(*result).SUITES_I_suite_l_suite_count, (zcbor_decoder_t *)zcbor_int32_decode, state, (&(*result).SUITES_I_suite_l_suite), sizeof(int32_t))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))) && (((*result).message_1_SUITES_I_choice = SUITES_I_suite_l_c), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_int32_decode(state, (&(*result).message_1_SUITES_I_int)))) && (((*result).message_1_SUITES_I_choice = message_1_SUITES_I_int_c), true)))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result).message_1_G_X))))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).message_1_C_I_int)))) && (((*result).message_1_C_I_choice = message_1_C_I_int_c), true))
	|| (((zcbor_bstr_decode(state, (&(*result).message_1_C_I_bstr)))) && (((*result).message_1_C_I_choice = message_1_C_I_bstr_c), true))), zcbor_union_end_code(state), int_res)))
	&& ((*result).message_1_ead_1_present = ((zcbor_bstr_decode(state, (&(*result).message_1_ead_1)))), 1))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_message_1(
		const uint8_t *payload, size_t payload_len,
		struct message_1 *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_message_1, sizeof(states) / sizeof(zcbor_state_t), 5);
}
