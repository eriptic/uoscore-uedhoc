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
#include "cbor/oscore_info.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_oscore_info(zcbor_state_t *state, const struct oscore_info *input);


static bool encode_oscore_info(
		zcbor_state_t *state, const struct oscore_info *input)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_list_start_encode(state, 5) && ((((zcbor_bstr_encode(state, (&(*input)._oscore_info_id))))
	&& ((((*input)._oscore_info_id_context_choice == _oscore_info_id_context_bstr) ? ((zcbor_bstr_encode(state, (&(*input)._oscore_info_id_context_bstr))))
	: (((*input)._oscore_info_id_context_choice == _oscore_info_id_context_nil) ? ((zcbor_nil_put(state, NULL)))
	: false)))
	&& ((((*input)._oscore_info_alg_aead_choice == _oscore_info_alg_aead_int) ? ((zcbor_int32_encode(state, (&(*input)._oscore_info_alg_aead_int))))
	: (((*input)._oscore_info_alg_aead_choice == _oscore_info_alg_aead_tstr) ? ((zcbor_tstr_encode(state, (&(*input)._oscore_info_alg_aead_tstr))))
	: false)))
	&& ((zcbor_tstr_encode(state, (&(*input)._oscore_info_type))))
	&& ((zcbor_uint32_encode(state, (&(*input)._oscore_info_L))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 5))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_encode_oscore_info(
		uint8_t *payload, size_t payload_len,
		const struct oscore_info *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 1);

	bool ret = encode_oscore_info(states, input);

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
