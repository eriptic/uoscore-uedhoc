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
#include "cbor/edhoc_encode_int_type.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_int_type_i(zcbor_state_t *state, const int32_t *input);


static bool encode_int_type_i(
		zcbor_state_t *state, const int32_t *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_int32_encode(state, (&(*input))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_int_type_i(
		uint8_t *payload, size_t payload_len,
		const int32_t *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_int_type_i, sizeof(states) / sizeof(zcbor_state_t), 1);
}
