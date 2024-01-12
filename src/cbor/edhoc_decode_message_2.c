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
#include "cbor/edhoc_decode_message_2.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_m2(zcbor_state_t *state, struct m2 *result);


static bool decode_m2(
		zcbor_state_t *state, struct m2 *result)
{
	zcbor_log("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_bstr_decode(state, (&(*result).m2_G_Y_CIPHERTEXT_2))))
	&& ((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result).m2_C_R_int)))) && (((*result).m2_C_R_choice = m2_C_R_int_c), true))
	|| (((zcbor_bstr_decode(state, (&(*result).m2_C_R_bstr)))) && (((*result).m2_C_R_choice = m2_C_R_bstr_c), true))), zcbor_union_end_code(state), int_res))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_m2(
		const uint8_t *payload, size_t payload_len,
		struct m2 *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_m2, sizeof(states) / sizeof(zcbor_state_t), 2);
}
