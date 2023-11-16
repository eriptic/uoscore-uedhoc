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
#include "cbor/oscore_aad_array.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_aad_array(zcbor_state_t *state, const struct aad_array *input);


static bool encode_aad_array(
		zcbor_state_t *state, const struct aad_array *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_list_start_encode(state, 5) && ((((zcbor_uint32_encode(state, (&(*input)._aad_array_oscore_version))))
	&& ((zcbor_list_start_encode(state, 1) && ((((((*input)._aad_array_algorithms_alg_aead_choice == _aad_array_algorithms_alg_aead_int) ? ((zcbor_int32_encode(state, (&(*input)._aad_array_algorithms_alg_aead_int))))
	: (((*input)._aad_array_algorithms_alg_aead_choice == _aad_array_algorithms_alg_aead_tstr) ? ((zcbor_tstr_encode(state, (&(*input)._aad_array_algorithms_alg_aead_tstr))))
	: false)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 1)))
	&& ((zcbor_bstr_encode(state, (&(*input)._aad_array_request_kid))))
	&& ((zcbor_bstr_encode(state, (&(*input)._aad_array_request_piv))))
	&& ((zcbor_bstr_encode(state, (&(*input)._aad_array_options))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 5))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_encode_aad_array(
		uint8_t *payload, size_t payload_len,
		const struct aad_array *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 1);

	bool ret = encode_aad_array(states, input);

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
