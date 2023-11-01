/*
 * Generated using zcbor version 0.7.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "cbor/edhoc_decode_plaintext.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_repeated_map_kid(zcbor_state_t *state, struct map_kid_ *result);
static bool decode_repeated_map_x5bag(zcbor_state_t *state, struct map_x5bag *result);
static bool decode_repeated_map_x5chain(zcbor_state_t *state, struct map_x5chain *result);
static bool decode_repeated_map_x5t(zcbor_state_t *state, struct map_x5t_ *result);
static bool decode_repeated_map_x5u(zcbor_state_t *state, struct map_x5u *result);
static bool decode_repeated_map_c5b(zcbor_state_t *state, struct map_c5b *result);
static bool decode_repeated_map_c5c(zcbor_state_t *state, struct map_c5c *result);
static bool decode_repeated_map_c5t(zcbor_state_t *state, struct map_c5t_ *result);
static bool decode_repeated_map_c5u(zcbor_state_t *state, struct map_c5u *result);
static bool decode_map(zcbor_state_t *state, struct map *result);
static bool decode_plaintext(zcbor_state_t *state, struct plaintext *result);


static bool decode_repeated_map_kid(
		zcbor_state_t *state, struct map_kid_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (4))))
	&& (zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result)._map_kid_int)))) && (((*result)._map_kid_choice = _map_kid_int), true))
	|| (((zcbor_bstr_decode(state, (&(*result)._map_kid_bstr)))) && (((*result)._map_kid_choice = _map_kid_bstr), true))), zcbor_union_end_code(state), int_res))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_x5bag(
		zcbor_state_t *state, struct map_x5bag *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (32))))
	&& (zcbor_bstr_decode(state, (&(*result)._map_x5bag)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_x5chain(
		zcbor_state_t *state, struct map_x5chain *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (33))))
	&& (zcbor_bstr_decode(state, (&(*result)._map_x5chain)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_x5t(
		zcbor_state_t *state, struct map_x5t_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (34))))
	&& (zcbor_list_start_decode(state) && ((((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result)._map_x5t_alg_int)))) && (((*result)._map_x5t_alg_choice = _map_x5t_alg_int), true))
	|| (((zcbor_tstr_decode(state, (&(*result)._map_x5t_alg_tstr)))) && (((*result)._map_x5t_alg_choice = _map_x5t_alg_tstr), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result)._map_x5t_hash))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_x5u(
		zcbor_state_t *state, struct map_x5u *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (35))))
	&& (zcbor_bstr_decode(state, (&(*result)._map_x5u)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_c5b(
		zcbor_state_t *state, struct map_c5b *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (52))))
	&& (zcbor_bstr_decode(state, (&(*result)._map_c5b)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_c5c(
		zcbor_state_t *state, struct map_c5c *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (53))))
	&& (zcbor_bstr_decode(state, (&(*result)._map_c5c)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_c5t(
		zcbor_state_t *state, struct map_c5t_ *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = ((((zcbor_uint32_expect(state, (54))))
	&& (zcbor_list_start_decode(state) && ((((zcbor_union_start_code(state) && (int_res = ((((zcbor_int32_decode(state, (&(*result)._map_c5t_alg_int)))) && (((*result)._map_c5t_alg_choice = _map_c5t_alg_int), true))
	|| (((zcbor_tstr_decode(state, (&(*result)._map_c5t_alg_tstr)))) && (((*result)._map_c5t_alg_choice = _map_c5t_alg_tstr), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result)._map_c5t_hash))))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_list_end_decode(state))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_repeated_map_c5u(
		zcbor_state_t *state, struct map_c5u *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = ((((zcbor_uint32_expect(state, (55))))
	&& (zcbor_bstr_decode(state, (&(*result)._map_c5u)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_map(
		zcbor_state_t *state, struct map *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((zcbor_map_start_decode(state) && ((zcbor_present_decode(&((*result)._map_kid_present), (zcbor_decoder_t *)decode_repeated_map_kid, state, (&(*result)._map_kid))
	&& zcbor_present_decode(&((*result)._map_x5bag_present), (zcbor_decoder_t *)decode_repeated_map_x5bag, state, (&(*result)._map_x5bag))
	&& zcbor_present_decode(&((*result)._map_x5chain_present), (zcbor_decoder_t *)decode_repeated_map_x5chain, state, (&(*result)._map_x5chain))
	&& zcbor_present_decode(&((*result)._map_x5t_present), (zcbor_decoder_t *)decode_repeated_map_x5t, state, (&(*result)._map_x5t))
	&& zcbor_present_decode(&((*result)._map_x5u_present), (zcbor_decoder_t *)decode_repeated_map_x5u, state, (&(*result)._map_x5u))
	&& zcbor_present_decode(&((*result)._map_c5b_present), (zcbor_decoder_t *)decode_repeated_map_c5b, state, (&(*result)._map_c5b))
	&& zcbor_present_decode(&((*result)._map_c5c_present), (zcbor_decoder_t *)decode_repeated_map_c5c, state, (&(*result)._map_c5c))
	&& zcbor_present_decode(&((*result)._map_c5t_present), (zcbor_decoder_t *)decode_repeated_map_c5t, state, (&(*result)._map_c5t))
	&& zcbor_present_decode(&((*result)._map_c5u_present), (zcbor_decoder_t *)decode_repeated_map_c5u, state, (&(*result)._map_c5u))) || (zcbor_list_map_end_force_decode(state), false)) && zcbor_map_end_decode(state))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}

static bool decode_plaintext(
		zcbor_state_t *state, struct plaintext *result)
{
	zcbor_print("%s\r\n", __func__);
	bool int_res;

	bool tmp_result = (((((zcbor_union_start_code(state) && (int_res = ((((decode_map(state, (&(*result)._plaintext_ID_CRED_x__map)))) && (((*result)._plaintext_ID_CRED_x_choice = _plaintext_ID_CRED_x__map), true))
	|| (zcbor_union_elem_code(state) && (((zcbor_bstr_decode(state, (&(*result)._plaintext_ID_CRED_x_bstr)))) && (((*result)._plaintext_ID_CRED_x_choice = _plaintext_ID_CRED_x_bstr), true)))
	|| (((zcbor_int32_decode(state, (&(*result)._plaintext_ID_CRED_x_int)))) && (((*result)._plaintext_ID_CRED_x_choice = _plaintext_ID_CRED_x_int), true))), zcbor_union_end_code(state), int_res)))
	&& ((zcbor_bstr_decode(state, (&(*result)._plaintext_SGN_or_MAC_x))))
	&& zcbor_present_decode(&((*result)._plaintext_AD_x_present), (zcbor_decoder_t *)zcbor_bstr_decode, state, (&(*result)._plaintext_AD_x)))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_decode_plaintext(
		const uint8_t *payload, size_t payload_len,
		struct plaintext *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[6];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 3);

	bool ret = decode_plaintext(states, result);

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
