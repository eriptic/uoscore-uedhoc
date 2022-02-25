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
#include "cbor/edhoc_encode_enc_structure.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif


static bool encode_edhoc_enc_structure(
		zcbor_state_t *state, const struct edhoc_enc_structure *input)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((zcbor_list_start_encode(state, 3) && (int_res = (((zcbor_tstr_encode(state, (&(*input)._edhoc_enc_structure_context))))
	&& ((zcbor_bstr_encode(state, (&(*input)._edhoc_enc_structure_protected))))
	&& ((zcbor_bstr_encode(state, (&(*input)._edhoc_enc_structure_external_aad))))), ((zcbor_list_end_encode(state, 3)) && int_res)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



bool cbor_encode_edhoc_enc_structure(
		uint8_t *payload, size_t payload_len,
		const struct edhoc_enc_structure *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[3];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 1);

	bool ret = encode_edhoc_enc_structure(states, input);

	if (ret && (payload_len_out != NULL)) {
		*payload_len_out = MIN(payload_len,
				(size_t)states[0].payload - (size_t)payload);
	}

	return ret;
}
