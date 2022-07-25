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
#include "edhoc/bstr_encode_decode.h"

#include "common/print_util.h"
#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/memcpy_s.h"

#include "cbor/edhoc_encode_enc_structure.h"
#include "cbor/edhoc_encode_sig_structure.h"

enum err mac(const uint8_t *prk, uint32_t prk_len, const uint8_t *th,
	     uint32_t th_len, const uint8_t *id_cred, uint32_t id_cred_len,
	     const uint8_t *cred, uint32_t cred_len, const uint8_t *ead,
	     uint32_t ead_len, enum info_label mac_label, bool static_dh,
	     struct suite *suite, uint8_t *mac, uint32_t *mac_len)
{
	/*encode th as bstr*/
	uint32_t th_encoded_len = th_len + 2;
	TRY(check_buffer_size(HASH_DEFAULT_SIZE + 2, th_encoded_len));
	uint8_t th_encoded[HASH_DEFAULT_SIZE + 2];
	TRY(encode_byte_string(th, th_len, th_encoded, &th_encoded_len));

	/**/
	uint32_t context_mac_len =
		id_cred_len + cred_len + ead_len + th_encoded_len;
	TRY(check_buffer_size(CONTEXT_MAC_DEFAULT_SIZE, context_mac_len));
	uint8_t context_mac[CONTEXT_MAC_DEFAULT_SIZE];
	TRY(_memcpy_s(context_mac, context_mac_len, id_cred, id_cred_len));

	TRY(_memcpy_s((context_mac + id_cred_len),
		      (context_mac_len - id_cred_len), th_encoded,
		      th_encoded_len));

	TRY(_memcpy_s((context_mac + id_cred_len + th_encoded_len),
		      (context_mac_len - id_cred_len - th_encoded_len), cred,
		      cred_len));

	if (0 < ead_len) {
    TRY(_memcpy_s(
      (context_mac + id_cred_len + th_encoded_len + cred_len),
      (context_mac_len - id_cred_len - th_encoded_len - cred_len),
      ead, ead_len));
	}


	PRINT_ARRAY("MAC context", context_mac, context_mac_len);

	if (static_dh) {
		*mac_len = suite->edhoc_mac_len_static_dh;

	} else {
		*mac_len = get_hash_len(suite->edhoc_hash);
	}

	TRY(edhoc_kdf(suite->edhoc_hash, prk, prk_len, mac_label, context_mac,
		      context_mac_len, *mac_len, mac));

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
	uint8_t th_enc[HASH_DEFAULT_SIZE + 2];
	uint32_t th_enc_len = sizeof(th_enc);

	TRY(encode_byte_string(th, th_len, th_enc, &th_enc_len));

	uint32_t tmp_len = th_enc_len + cred_len + ead_len;

	TRY(check_buffer_size(CRED_DEFAULT_SIZE + HASH_DEFAULT_SIZE +
				      AD_DEFAULT_SIZE,
			      tmp_len));
	uint8_t tmp[CRED_DEFAULT_SIZE + HASH_DEFAULT_SIZE + AD_DEFAULT_SIZE];

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

enum err signature_or_mac(enum sgn_or_mac_op op, bool static_dh,
			  struct suite *suite, const uint8_t *sk,
			  uint32_t sk_len, const uint8_t *pk, uint32_t pk_len,
			  const uint8_t *prk, uint32_t prk_len,
			  const uint8_t *th, uint32_t th_len,
			  const uint8_t *id_cred, uint32_t id_cred_len,
			  const uint8_t *cred, uint32_t cred_len,
			  const uint8_t *ead, uint32_t ead_len,
			  enum info_label mac_label, uint8_t *signature_or_mac,
			  uint32_t *signature_or_mac_len)
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
		TRY(check_buffer_size(HASH_DEFAULT_SIZE, mac_buf_len));
		uint8_t mac_buf[HASH_DEFAULT_SIZE];

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
			PRINT_ARRAY("pk", pk, pk_len);
			PRINT_ARRAY("signature_struct", signature_struct,
				    signature_struct_len);
			PRINT_ARRAY("signature_or_mac", signature_or_mac,
				    *signature_or_mac_len);

			TRY(verify(suite->edhoc_sign, pk, pk_len,
				   signature_struct, signature_struct_len,
				   signature_or_mac, *signature_or_mac_len,
				   &result));
			if (!result) {
				return signature_authentication_failed;
			}
			PRINT_MSG(
				"Signature or MAC verification successful!\n");
		}
	}
	return ok;
}
