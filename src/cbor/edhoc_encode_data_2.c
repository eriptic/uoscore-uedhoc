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
#include "cbor/edhoc_encode_data_2.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_repeated_data_2_C_I(zcbor_state_t *state, const struct data_2_C_I_ *input);
static bool encode_data_2(zcbor_state_t *state, const struct data_2 *input);


static bool encode_repeated_data_2_C_I(
		zcbor_state_t *state, const struct data_2_C_I_ *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((*input)._data_2_C_I_choice == _data_2_C_I_int) ? ((zcbor_int32_encode(state, (&(*input)._data_2_C_I_int))))
	: (((*input)._data_2_C_I_choice == _data_2_C_I_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._data_2_C_I_bstr))))
	: false))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool encode_data_2(
		zcbor_state_t *state, const struct data_2 *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_present_encode(&((*input)._data_2_C_I_present), (zcbor_encoder_t *)encode_repeated_data_2_C_I, state, (&(*input)._data_2_C_I))
	&& ((zcbor_bstr_encode(state, (&(*input)._data_2_G_Y))))
	&& ((((*input)._data_2_C_R_choice == _data_2_C_R_int) ? ((zcbor_int32_encode(state, (&(*input)._data_2_C_R_int))))
	: (((*input)._data_2_C_R_choice == _data_2_C_R_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._data_2_C_R_bstr))))
	: false))))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_encode_data_2(
		uint8_t *payload, size_t payload_len,
		const struct data_2 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 3);

	bool ret = encode_data_2(states, input);

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
