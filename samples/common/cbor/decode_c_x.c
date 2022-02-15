/*
 * Generated using zcbor version 0.3.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "decode_c_x.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


static bool decode_cx_C_X(
		zcbor_state_t *state, struct cx_C_X_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_bstr_decode(state, (&(*result)._cx_C_X_bstr)))) && (((*result)._cx_C_X_choice = _cx_C_X_bstr) || 1))
	|| (((zcbor_int32_decode(state, (&(*result)._cx_C_X_int)))) && (((*result)._cx_C_X_choice = _cx_C_X_int) || 1))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



bool cbor_decode_cx_C_X(
		const uint8_t *payload, size_t payload_len,
		struct cx_C_X_ *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 1);

	bool ret = decode_cx_C_X(states, result);

	if (ret && (payload_len_out != NULL)) {
		*payload_len_out = MIN(payload_len,
				(size_t)states[0].payload - (size_t)payload);
	}

	return ret;
}
