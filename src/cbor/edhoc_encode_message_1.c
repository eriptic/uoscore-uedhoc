/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "cbor/edhoc_encode_message_1.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_message_1(zcbor_state_t *state, const struct message_1 *input);


static bool encode_message_1(
		zcbor_state_t *state, const struct message_1 *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_encode(state, (&(*input)._message_1_METHOD))))
	&& ((((*input)._message_1_SUITES_I_choice == _SUITES_I__suite) ? ((zcbor_list_start_encode(state, 10) && ((zcbor_multi_encode_minmax(2, 10, &(*input)._SUITES_I__suite_suite_count, (zcbor_encoder_t *)zcbor_int32_encode, state, (&(*input)._SUITES_I__suite_suite), sizeof(int32_t))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 10)))
	: (((*input)._message_1_SUITES_I_choice == _message_1_SUITES_I_int) ? ((zcbor_int32_encode(state, (&(*input)._message_1_SUITES_I_int))))
	: false)))
	&& ((zcbor_bstr_encode(state, (&(*input)._message_1_G_X))))
	&& ((((*input)._message_1_C_I_choice == _message_1_C_I_int) ? ((zcbor_int32_encode(state, (&(*input)._message_1_C_I_int))))
	: (((*input)._message_1_C_I_choice == _message_1_C_I_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._message_1_C_I_bstr))))
	: false)))
	&& zcbor_present_encode(&((*input)._message_1_ead_1_present), (zcbor_encoder_t *)zcbor_bstr_encode, state, (&(*input)._message_1_ead_1)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_encode_message_1(
		uint8_t *payload, size_t payload_len,
		const struct message_1 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 5);

	bool ret = encode_message_1(states, input);

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
