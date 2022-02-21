/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdint.h>

#include "edhoc.h"
#include "edhoc/edhoc_cose.h"
#include "edhoc/hkdf_info.h"
#include "edhoc/okm.h"
#include "edhoc/suites.h"
#include "edhoc/signature_or_mac_msg.h"

#include "common/print_util.h"
#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"

#include "cbor/edhoc_encode_enc_structure.h"
#include "cbor/edhoc_encode_sig_structure.h"
#include "cbor/edhoc_encode_bstr_type.h"
#include "cbor/edhoc_decode_bstr_type.h"

enum err encode_byte_string(const uint8_t *in, uint32_t in_len, uint8_t *out,
			    uint32_t *out_len)
{
	size_t payload_len_out;
	struct zcbor_string tmp;
	tmp.value = in;
	tmp.len = in_len;
	TRY_EXPECT(cbor_encode_bstr_type_b_str(out, *out_len, &tmp,
					       &payload_len_out),
		   true);
	*out_len = (uint32_t) payload_len_out;
	return ok;
}

enum err decode_byte_string(const uint8_t *in, const uint32_t in_len,
			    uint8_t *out, uint32_t *out_len)
{
	struct zcbor_string str;
	size_t decode_len = 0;

	TRY_EXPECT(cbor_decode_bstr_type_b_str(in, in_len, &str, &decode_len),
		   true);

	TRY(_memcpy_s(out, *out_len, str.value, (uint32_t) str.len));
	*out_len = (uint32_t) str.len;

	return ok;
}

enum err mac(const uint8_t *prk, uint32_t prk_len, const uint8_t *th,
	     uint32_t th_len, const uint8_t *id_cred, uint32_t id_cred_len,
	     const uint8_t *cred, uint32_t cred_len, const uint8_t *ead,
	     uint32_t ead_len, const char *mac_label, bool static_dh,
	     struct suite *suite, uint8_t *mac, uint32_t *mac_len)
{
	uint32_t context_mac_len = id_cred_len + cred_len + ead_len;
	TRY(check_buffer_size(CONTEXT_MAC_DEFAULT_SIZE, context_mac_len));
	uint8_t context_mac[CONTEXT_MAC_DEFAULT_SIZE];
	TRY(_memcpy_s(context_mac, context_mac_len, id_cred, id_cred_len));

	TRY(_memcpy_s((context_mac + id_cred_len),
		      (context_mac_len - id_cred_len), cred, cred_len));

	TRY(_memcpy_s((context_mac + id_cred_len + cred_len),
		      (context_mac_len - id_cred_len - cred_len), ead,
		      ead_len));

	PRINT_ARRAY("MAC context", context_mac, context_mac_len);

	if (static_dh) {
		*mac_len = suite->edhoc_mac_len_static_dh;

	} else {
		*mac_len = get_hash_len(suite->edhoc_hash);
	}

	TRY(okm_calc(suite->edhoc_hash, prk, prk_len, th, th_len, mac_label,
		     context_mac, context_mac_len, mac, *mac_len));

	PRINT_ARRAY("MAC 2/3", mac, *mac_len);
	return ok;
}

static enum err signature_struct_gen(const uint8_t *th, uint32_t th_len,
				     const uint8_t *id_cred,
				     uint32_t id_cred_len, const uint8_t *cred,
				     uint32_t cred_len, const uint8_t *ead,
				     uint32_t ead_len, const uint8_t *mac,
				     uint32_t mac_len, uint8_t *out,
				     uint32_t *out_len)
{
	uint8_t th_enc[SHA_DEFAULT_SIZE + 2];
	uint32_t th_enc_len = sizeof(th_enc);

	TRY(encode_byte_string(th, th_len, th_enc, &th_enc_len));

	uint32_t tmp_len = th_enc_len + cred_len + ead_len;

	TRY(check_buffer_size(CRED_DEFAULT_SIZE + SHA_DEFAULT_SIZE +
				      AD_DEFAULT_SIZE,
			      tmp_len));
	uint8_t tmp[CRED_DEFAULT_SIZE + SHA_DEFAULT_SIZE + AD_DEFAULT_SIZE];

	memcpy(tmp, th_enc, th_enc_len);
	memcpy(tmp + th_enc_len, cred, cred_len);
	if (ead_len != 0) {
		memcpy(tmp + th_enc_len + cred_len, ead, ead_len);
	}

	uint8_t context_str[] = { "Signature1" };
	TRY(cose_sig_structure_encode(
		context_str, (uint32_t)strlen((char *)context_str), id_cred,
		id_cred_len, tmp, tmp_len, mac, mac_len, out, out_len));
	PRINT_ARRAY("COSE_Sign1 object to be signed", out, *out_len);
	return ok;
}

enum err
signature_or_mac(enum sgn_or_mac_op op, bool static_dh, struct suite *suite,
		 const uint8_t *sk, uint32_t sk_len, const uint8_t *pk,
		 uint32_t pk_len, const uint8_t *prk, uint32_t prk_len,
		 const uint8_t *th, uint32_t th_len, const uint8_t *id_cred,
		 uint32_t id_cred_len, const uint8_t *cred, uint32_t cred_len,
		 const uint8_t *ead, uint32_t ead_len, const char *mac_label,
		 uint8_t *signature_or_mac, uint32_t *signature_or_mac_len)
{
	if (op == GENERATE) {
		/*we always calculate the mac*/
		TRY(mac(prk, prk_len, th, th_len, id_cred, id_cred_len, cred,
			cred_len, ead, ead_len, mac_label, static_dh, suite,
			signature_or_mac, signature_or_mac_len));

		if (static_dh) {
			/*signature_or_mac is mac when the caller of this function authenticates with static DH keys*/
			return ok;
		} else {
			uint8_t signature_struct[SIGNATURE_STRUCT_DEFAULT_SIZE];
			uint32_t signature_struct_len =
				sizeof(signature_struct);
			TRY(signature_struct_gen(
				th, th_len, id_cred, id_cred_len, cred,
				cred_len, ead, ead_len, signature_or_mac,
				*signature_or_mac_len, signature_struct,
				&signature_struct_len));

			*signature_or_mac_len =
				get_signature_len(suite->edhoc_sign);

			TRY(sign(suite->edhoc_sign, sk, sk_len, pk,
				 signature_struct, signature_struct_len,
				 signature_or_mac));
			PRINT_ARRAY("signature_or_mac (is signature)",
				    signature_or_mac, *signature_or_mac_len);
		}
	} else { /*we verify here*/
		uint32_t mac_buf_len = get_hash_len(suite->edhoc_hash);
		TRY(check_buffer_size(SHA_DEFAULT_SIZE, mac_buf_len));
		uint8_t mac_buf[SHA_DEFAULT_SIZE];

		TRY(mac(prk, prk_len, th, th_len, id_cred, id_cred_len, cred,
			cred_len, ead, ead_len, mac_label, static_dh, suite,
			mac_buf, &mac_buf_len));

		if (static_dh) {
			/*signature_or_mac is mac when the caller of this function authenticates with static DH keys*/

			if (0 != memcmp(mac_buf, signature_or_mac,
					*signature_or_mac_len)) {
				return mac_authentication_failed;
			}

		} else {
			uint8_t signature_struct[SIGNATURE_STRUCT_DEFAULT_SIZE];
			uint32_t signature_struct_len =
				sizeof(signature_struct);
			TRY(signature_struct_gen(
				th, th_len, id_cred, id_cred_len, cred,
				cred_len, ead, ead_len, mac_buf, mac_buf_len,
				signature_struct, &signature_struct_len));

			bool result;
			TRY(verify(suite->edhoc_sign, pk, pk_len,
				   signature_struct, signature_struct_len,
				   signature_or_mac, *signature_or_mac_len,
				   &result));
			if (!result) {
				return signature_authentication_failed;
			}
			PRINT_MSG(
				"Signature or MAC verification successfull!\n");
		}
	}
	return ok;
}
