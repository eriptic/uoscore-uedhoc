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
#include "cbor/edhoc_decode_cert.h"

#if DEFAULT_MAX_QTY != 3
#error "The type file was generated with a different default_max_qty than this file"
#endif

static bool decode_cert(zcbor_state_t *state, struct cert *result);


static bool decode_cert(
		zcbor_state_t *state, struct cert *result)
{
	zcbor_print("%s\r\n", __func__);

	bool tmp_result = (((((zcbor_int32_decode(state, (&(*result)._cert_type))))
	&& ((zcbor_int32_decode(state, (&(*result)._cert_serial_number))))
	&& ((zcbor_tstr_decode(state, (&(*result)._cert_issuer))))
	&& ((zcbor_int32_decode(state, (&(*result)._cert_validity_not_before))))
	&& ((zcbor_int32_decode(state, (&(*result)._cert_validity_not_after))))
	&& ((zcbor_bstr_decode(state, (&(*result)._cert_subject))))
	&& ((zcbor_int32_decode(state, (&(*result)._cert_subject_public_key_algorithm))))
	&& ((zcbor_bstr_decode(state, (&(*result)._cert_pk))))
	&& ((zcbor_int32_decode(state, (&(*result)._cert_extensions))))
	&& ((zcbor_int32_decode(state, (&(*result)._cert_issuer_signature_algorithm))))
	&& ((zcbor_bstr_decode(state, (&(*result)._cert_signature)))))));

	if (!tmp_result)
		zcbor_trace();

	return tmp_result;
}



int cbor_decode_cert(
		const uint8_t *payload, size_t payload_len,
		struct cert *result,
		size_t *payload_len_out)
{
	zcbor_state_t states[2];

	zcbor_new_state(states, sizeof(states) / sizeof(zcbor_state_t), payload, payload_len, 11);

	bool ret = decode_cert(states, result);

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
