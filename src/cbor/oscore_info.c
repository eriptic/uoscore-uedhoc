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
#include "cbor/oscore_info.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_oscore_info(zcbor_state_t *state, const struct oscore_info *input);


static bool encode_oscore_info(
		zcbor_state_t *state, const struct oscore_info *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_list_start_encode(state, 5) && ((((zcbor_bstr_encode(state, (&(*input).oscore_info_id))))
	&& ((((*input).oscore_info_id_context_choice == oscore_info_id_context_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).oscore_info_id_context_bstr))))
	: (((*input).oscore_info_id_context_choice == oscore_info_id_context_nil_c) ? ((zcbor_nil_put(state, NULL)))
	: false)))
	&& ((((*input).oscore_info_alg_aead_choice == oscore_info_alg_aead_int_c) ? ((zcbor_int32_encode(state, (&(*input).oscore_info_alg_aead_int))))
	: (((*input).oscore_info_alg_aead_choice == oscore_info_alg_aead_tstr_c) ? ((zcbor_tstr_encode(state, (&(*input).oscore_info_alg_aead_tstr))))
	: false)))
	&& ((zcbor_tstr_encode(state, (&(*input).oscore_info_type))))
	&& ((zcbor_uint32_encode(state, (&(*input).oscore_info_L))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 5))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_oscore_info(
		uint8_t *payload, size_t payload_len,
		const struct oscore_info *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[4];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_oscore_info, sizeof(states) / sizeof(zcbor_state_t), 1);
}
