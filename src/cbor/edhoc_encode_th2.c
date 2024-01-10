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
#include "cbor/edhoc_encode_th2.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_th2(zcbor_state_t *state, const struct th2 *input);


static bool encode_th2(
		zcbor_state_t *state, const struct th2 *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_bstr_encode(state, (&(*input).th2_G_Y))))
	&& ((((*input).th2_C_R_choice == th2_C_R_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).th2_C_R_bstr))))
	: (((*input).th2_C_R_choice == th2_C_R_int_c) ? ((zcbor_int32_encode(state, (&(*input).th2_C_R_int))))
	: false)))
	&& ((zcbor_bstr_encode(state, (&(*input).th2_hash_msg1)))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_th2(
		uint8_t *payload, size_t payload_len,
		const struct th2 *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_th2, sizeof(states) / sizeof(zcbor_state_t), 3);
}
