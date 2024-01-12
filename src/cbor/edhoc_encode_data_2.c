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
#include "cbor/edhoc_encode_data_2.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_repeated_data_2_C_I(zcbor_state_t *state, const struct data_2_C_I_r *input);
static bool encode_data_2(zcbor_state_t *state, const struct data_2 *input);


static bool encode_repeated_data_2_C_I(
		zcbor_state_t *state, const struct data_2_C_I_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((*input).data_2_C_I_choice == data_2_C_I_int_c) ? ((zcbor_int32_encode(state, (&(*input).data_2_C_I_int))))
	: (((*input).data_2_C_I_choice == data_2_C_I_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).data_2_C_I_bstr))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_data_2(
		zcbor_state_t *state, const struct data_2 *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((!(*input).data_2_C_I_present || encode_repeated_data_2_C_I(state, (&(*input).data_2_C_I)))
	&& ((zcbor_bstr_encode(state, (&(*input).data_2_G_Y))))
	&& ((((*input).data_2_C_R_choice == data_2_C_R_int_c) ? ((zcbor_int32_encode(state, (&(*input).data_2_C_R_int))))
	: (((*input).data_2_C_R_choice == data_2_C_R_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).data_2_C_R_bstr))))
	: false))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_data_2(
		uint8_t *payload, size_t payload_len,
		const struct data_2 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_data_2, sizeof(states) / sizeof(zcbor_state_t), 3);
}
