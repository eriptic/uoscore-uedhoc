/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "cbor/edhoc_decode_message_1.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_message_1(zcbor_state_t *state, struct message_1 *result);


static bool decode_message_1(
		zcbor_state_t *state, struct message_1 *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result)._message_1_METHOD))))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_list_start_decode(state) && ((zcbor_multi_decode(2, 10, &(*result)._SUITES_I__suite_suite_count, (zcbor_decoder_t *)zcbor_int32_decode, state, (&(*result)._SUITES_I__suite_suite), sizeof(int32_t))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))) && (((*result)._message_1_SUITES_I_choice = _SUITES_I__suite), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_int32_decode(state, (&(*result)._message_1_SUITES_I_int)))) && (((*result)._message_1_SUITES_I_choice = _message_1_SUITES_I_int), true)))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result)._message_1_G_X))))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result)._message_1_C_I_int)))) && (((*result)._message_1_C_I_choice = _message_1_C_I_int), true))
	|| (((zcbor_bstr_decode(state, (&(*result)._message_1_C_I_bstr)))) && (((*result)._message_1_C_I_choice = _message_1_C_I_bstr), true))), zcbor_union_end_code(state), int_res)))
	&& zcbor_present_decode(&((*result)._message_1_ead_1_present), (zcbor_decoder_t *)zcbor_bstr_decode, state, (&(*result)._message_1_ead_1)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_decode_message_1(
		const uint8_t *payload, size_t payload_len,
		struct message_1 *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 5);

	bool ret = decode_message_1(states, result);

	if (ret && (payload_len_out != NULL)) {
		*payload_len_out = MIN(payload_len,
				(size_t)states[0].payload - (size_t)payload);
	}

	if (!ret) {
		int err = zcbor_pop_error(states);

		zcbor_print("Return error: %d\r\n", err);
		return (err == ZCBOR_SUCCESS) ? ZCBOR_ERR_UNKNOWN : err;
	}
	return ZCBOR_SUCCESS;
}
