/*
 * Generated using zcbor version 0.3.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_encode.h"
#include "cbor/edhoc_encode_info.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


static bool encode_info(
		zcbor_state_t *state, const struct info *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_uint32_encode(state, (&(*input)._info_label))))
	&& ((zcbor_bstr_encode(state, (&(*input)._info_context))))
	&& ((zcbor_uint32_encode(state, (&(*input)._info_length)))))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



bool cbor_encode_info(
		uint8_t *payload, size_t payload_len,
		const struct info *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 3);

	bool ret = encode_info(states, input);

	if (ret && (payload_len_out != NULL)) {
		*payload_len_out = MIN(payload_len,
				(size_t)states[0].payload - (size_t)payload);
	}

	return ret;
}
