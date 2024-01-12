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
#include "cbor/edhoc_encode_id_cred_x.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool encode_repeated_id_cred_x_map_kid(zcbor_state_t *state, const struct id_cred_x_map_kid_r *input);
static bool encode_repeated_id_cred_x_map_x5bag(zcbor_state_t *state, const struct id_cred_x_map_x5bag *input);
static bool encode_repeated_id_cred_x_map_x5chain(zcbor_state_t *state, const struct id_cred_x_map_x5chain *input);
static bool encode_repeated_id_cred_x_map_x5t(zcbor_state_t *state, const struct id_cred_x_map_x5t_r *input);
static bool encode_repeated_id_cred_x_map_x5u(zcbor_state_t *state, const struct id_cred_x_map_x5u *input);
static bool encode_repeated_id_cred_x_map_c5b(zcbor_state_t *state, const struct id_cred_x_map_c5b *input);
static bool encode_repeated_id_cred_x_map_c5c(zcbor_state_t *state, const struct id_cred_x_map_c5c *input);
static bool encode_repeated_id_cred_x_map_c5t(zcbor_state_t *state, const struct id_cred_x_map_c5t_r *input);
static bool encode_repeated_id_cred_x_map_c5u(zcbor_state_t *state, const struct id_cred_x_map_c5u *input);
static bool encode_id_cred_x_map(zcbor_state_t *state, const struct id_cred_x_map *input);


static bool encode_repeated_id_cred_x_map_kid(
		zcbor_state_t *state, const struct id_cred_x_map_kid_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (4))))
	&& (((*input).id_cred_x_map_kid_choice == id_cred_x_map_kid_int_c) ? ((zcbor_int32_encode(state, (&(*input).id_cred_x_map_kid_int))))
	: (((*input).id_cred_x_map_kid_choice == id_cred_x_map_kid_bstr_c) ? ((zcbor_bstr_encode(state, (&(*input).id_cred_x_map_kid_bstr))))
	: false))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_id_cred_x_map_x5bag(
		zcbor_state_t *state, const struct id_cred_x_map_x5bag *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (32))))
	&& (zcbor_bstr_encode(state, (&(*input).id_cred_x_map_x5bag)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_id_cred_x_map_x5chain(
		zcbor_state_t *state, const struct id_cred_x_map_x5chain *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (33))))
	&& (zcbor_bstr_encode(state, (&(*input).id_cred_x_map_x5chain)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_id_cred_x_map_x5t(
		zcbor_state_t *state, const struct id_cred_x_map_x5t_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (34))))
	&& (zcbor_list_start_encode(state, 2) && ((((((*input).id_cred_x_map_x5t_alg_choice == id_cred_x_map_x5t_alg_int_c) ? ((zcbor_int32_encode(state, (&(*input).id_cred_x_map_x5t_alg_int))))
	: (((*input).id_cred_x_map_x5t_alg_choice == id_cred_x_map_x5t_alg_tstr_c) ? ((zcbor_tstr_encode(state, (&(*input).id_cred_x_map_x5t_alg_tstr))))
	: false)))
	&& ((zcbor_bstr_encode(state, (&(*input).id_cred_x_map_x5t_hash))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_id_cred_x_map_x5u(
		zcbor_state_t *state, const struct id_cred_x_map_x5u *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (35))))
	&& (zcbor_bstr_encode(state, (&(*input).id_cred_x_map_x5u)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_id_cred_x_map_c5b(
		zcbor_state_t *state, const struct id_cred_x_map_c5b *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (52))))
	&& (zcbor_bstr_encode(state, (&(*input).id_cred_x_map_c5b)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_id_cred_x_map_c5c(
		zcbor_state_t *state, const struct id_cred_x_map_c5c *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (53))))
	&& (zcbor_bstr_encode(state, (&(*input).id_cred_x_map_c5c)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_id_cred_x_map_c5t(
		zcbor_state_t *state, const struct id_cred_x_map_c5t_r *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (54))))
	&& (zcbor_list_start_encode(state, 2) && ((((((*input).id_cred_x_map_c5t_alg_choice == id_cred_x_map_c5t_alg_int_c) ? ((zcbor_int32_encode(state, (&(*input).id_cred_x_map_c5t_alg_int))))
	: (((*input).id_cred_x_map_c5t_alg_choice == id_cred_x_map_c5t_alg_tstr_c) ? ((zcbor_tstr_encode(state, (&(*input).id_cred_x_map_c5t_alg_tstr))))
	: false)))
	&& ((zcbor_bstr_encode(state, (&(*input).id_cred_x_map_c5t_hash))))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_list_end_encode(state, 2))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_repeated_id_cred_x_map_c5u(
		zcbor_state_t *state, const struct id_cred_x_map_c5u *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_put(state, (55))))
	&& (zcbor_bstr_encode(state, (&(*input).id_cred_x_map_c5u)))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}

static bool encode_id_cred_x_map(
		zcbor_state_t *state, const struct id_cred_x_map *input)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_encode(state, 9) && (((!(*input).id_cred_x_map_kid_present || encode_repeated_id_cred_x_map_kid(state, (&(*input).id_cred_x_map_kid)))
	&& (!(*input).id_cred_x_map_x5bag_present || encode_repeated_id_cred_x_map_x5bag(state, (&(*input).id_cred_x_map_x5bag)))
	&& (!(*input).id_cred_x_map_x5chain_present || encode_repeated_id_cred_x_map_x5chain(state, (&(*input).id_cred_x_map_x5chain)))
	&& (!(*input).id_cred_x_map_x5t_present || encode_repeated_id_cred_x_map_x5t(state, (&(*input).id_cred_x_map_x5t)))
	&& (!(*input).id_cred_x_map_x5u_present || encode_repeated_id_cred_x_map_x5u(state, (&(*input).id_cred_x_map_x5u)))
	&& (!(*input).id_cred_x_map_c5b_present || encode_repeated_id_cred_x_map_c5b(state, (&(*input).id_cred_x_map_c5b)))
	&& (!(*input).id_cred_x_map_c5c_present || encode_repeated_id_cred_x_map_c5c(state, (&(*input).id_cred_x_map_c5c)))
	&& (!(*input).id_cred_x_map_c5t_present || encode_repeated_id_cred_x_map_c5t(state, (&(*input).id_cred_x_map_c5t)))
	&& (!(*input).id_cred_x_map_c5u_present || encode_repeated_id_cred_x_map_c5u(state, (&(*input).id_cred_x_map_c5u)))) || (zcbor_list_map_end_force_encode(state), false)) && zcbor_map_end_encode(state, 9))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_encode_id_cred_x_map(
		uint8_t *payload, size_t payload_len,
		const struct id_cred_x_map *input,
		size_t *payload_len_out)
{
	zcbor_state_t states[5];

	return zcbor_entry_function(payload, payload_len, (void *)input, payload_len_out, states,
		(zcbor_decoder_t *)encode_id_cred_x_map, sizeof(states) / sizeof(zcbor_state_t), 1);
}
