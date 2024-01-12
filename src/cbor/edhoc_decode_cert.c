/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <string.h>
#include "zcbor_decode.h"
#include "cbor/edhoc_decode_cert.h"
#include "zcbor_print.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_cert(zcbor_state_t *state, struct cert *result);


static bool decode_cert(
		zcbor_state_t *state, struct cert *result)
{
	zcbor_log("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result).cert_type))))
	&& ((zcbor_int32_decode(state, (&(*result).cert_serial_number))))
	&& ((zcbor_tstr_decode(state, (&(*result).cert_issuer))))
	&& ((zcbor_int32_decode(state, (&(*result).cert_validity_not_before))))
	&& ((zcbor_int32_decode(state, (&(*result).cert_validity_not_after))))
	&& ((zcbor_bstr_decode(state, (&(*result).cert_subject))))
	&& ((zcbor_int32_decode(state, (&(*result).cert_subject_public_key_algorithm))))
	&& ((zcbor_bstr_decode(state, (&(*result).cert_pk))))
	&& ((zcbor_int32_decode(state, (&(*result).cert_extensions))))
	&& ((zcbor_int32_decode(state, (&(*result).cert_issuer_signature_algorithm))))
	&& ((zcbor_bstr_decode(state, (&(*result).cert_signature)))))));

	if (!tmp_result) {
		zcbor_trace_file(state);
		zcbor_log("%s error: %s\r\n", __func__, zcbor_error_str(zcbor_peek_error(state)));
	} else {
		zcbor_log("%s success\r\n", __func__);
	}

	return tmp_result;
}



int cbor_decode_cert(
		const uint8_t *payload, size_t payload_len,
		struct cert *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	return zcbor_entry_function(payload, payload_len, (void *)result, payload_len_out, states,
		(zcbor_decoder_t *)decode_cert, sizeof(states) / sizeof(zcbor_state_t), 11);
}
