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
#include "cbor/edhoc_encode_bstr_type.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_bstr_type_b_str(zcbor_state_t *state, const struct zcbor_string *input);


static bool encode_bstr_type_b_str(
		zcbor_state_t *state, const struct zcbor_string *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_bstr_encode(state, (&(*input))))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_encode_bstr_type_b_str(
		uint8_t *payload, size_t payload_len,
		const struct zcbor_string *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 1);

	bool ret = encode_bstr_type_b_str(states, input);

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
