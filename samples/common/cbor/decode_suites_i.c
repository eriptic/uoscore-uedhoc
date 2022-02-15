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
#include "decode_suites_i.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


static bool decode_suites(
		zcbor_state_t *state, struct suites_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_union_start_code(state) && (int_res = ((((zcbor_list_start_decode(state) && (int_res = (zcbor_multi_decode(2, 3, &(*result)._suites__int_int_count, (void *)zcbor_int32_decode, state, (&(*result)._suites__int_int), sizeof(int32_t))), ((zcbor_list_end_decode(state)) && int_res)))) && (((*result)._suites_choice = _suites__int) || 1))
	|| (zcbor_union_elem_code(state) && (((zcbor_int32_decode(state, (&(*result)._suites_int)))) && (((*result)._suites_choice = _suites_int) || 1)))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



bool cbor_decode_suites(
		const uint8_t *payload, size_t payload_len,
		struct suites_ *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 1);

	bool ret = decode_suites(states, result);

	if (ret && (payload_len_out != NULL)) {
		*payload_len_out = MIN(payload_len,
				(size_t)states[0].payload - (size_t)payload);
	}

	return ret;
}
