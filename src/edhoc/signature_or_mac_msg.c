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

#include "edhoc/buffer_sizes.h"
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

/**
 * @brief 			Forms a serialized data structure from a set of 
 * 				data items and computes a MAC over it.
 * 
 * @param[in] prk 		The key to be used for the mac.
 * @param[in] th 		Transcript hash.
 * @param[in] id_cred 		ID of the credential.
 * @param[in] cred 		The credential.
 * @param[in] ead 		External authorization data.
 * @param mac_label 		An info label.
 * @param static_dh 		True if static DH is used for authentication.
 * @param suite 		The used crypto suite.
 * @param[out] mac 		The computed mac.
 * @return 			Ok or error code.
 */
static enum err mac(const struct byte_array *prk, const struct byte_array *th,
		    const struct byte_array *id_cred,
		    const struct byte_array *cred, const struct byte_array *ead,
		    enum info_label mac_label, bool static_dh,
		    struct suite *suite, struct byte_array *mac)
{
	/*encode th as bstr*/
	BYTE_ARRAY_NEW(th_enc, HASH_SIZE + 2, th->len + 2);

	TRY(encode_bstr(th, &th_enc));

	/**/
	BYTE_ARRAY_NEW(context_mac, CONTEXT_MAC_SIZE,
		       id_cred->len + cred->len + ead->len + th_enc.len);

	TRY(_memcpy_s(context_mac.ptr, context_mac.len, id_cred->ptr,
		      id_cred->len));

	TRY(_memcpy_s((context_mac.ptr + id_cred->len),
		      (context_mac.len - id_cred->len), th_enc.ptr,
		      th_enc.len));

	TRY(_memcpy_s((context_mac.ptr + id_cred->len + th_enc.len),
		      (context_mac.len - id_cred->len - th_enc.len), cred->ptr,
		      cred->len));

	if (0 < ead->len) {
		TRY(_memcpy_s((context_mac.ptr + id_cred->len + th_enc.len +
			       cred->len),
			      (context_mac.len - id_cred->len - th_enc.len -
			       cred->len),
			      ead->ptr, ead->len));
	}

	PRINT_ARRAY("MAC context", context_mac.ptr, context_mac.len);

	if (static_dh) {
		mac->len = suite->edhoc_mac_len_static_dh;

	} else {
		mac->len = get_hash_len(suite->edhoc_hash);
	}

	TRY(edhoc_kdf(suite->edhoc_hash, prk, mac_label, &context_mac, mac));

	PRINT_ARRAY("MAC 2/3", mac->ptr, mac->len);
	return ok;
}

/**
 * @brief			Creates a byte array to be ready for signing. 
 * 
 * @param[in] th 		Transcript hash.
 * @param[in] id_cred 		Id of the credential.
 * @param[in] cred 		The credential.
 * @param[in] ead 		External Authorization Data. 
 * @param[in] mac 		Message Authentication Code. 
 * @param[out] out 		The result.
 * @return 			Ok or error code.
 */
static enum err signature_struct_gen(const struct byte_array *th,
				     const struct byte_array *id_cred,
				     const struct byte_array *cred,
				     const struct byte_array *ead,
				     const struct byte_array *mac,
				     struct byte_array *out)
{
	BYTE_ARRAY_NEW(th_enc, HASH_SIZE + 2, HASH_SIZE + 2);

	TRY(encode_bstr(th, &th_enc));

	BYTE_ARRAY_NEW(
		tmp, (CRED_MAX_SIZE + HASH_SIZE + EAD_SIZE + ENCODING_OVERHEAD),
		(th_enc.len + cred->len + ead->len));

	memcpy(tmp.ptr, th_enc.ptr, th_enc.len);
	memcpy(tmp.ptr + th_enc.len, cred->ptr, cred->len);
	if (ead->len != 0) {
		memcpy(tmp.ptr + th_enc.len + cred->len, ead->ptr, ead->len);
	}

	uint8_t context_str[] = { "Signature1" };
	struct byte_array str = BYTE_ARRAY_INIT(
		context_str, (uint32_t)strlen((char *)context_str));

	TRY(cose_sig_structure_encode(&str, id_cred, &tmp, mac, out));
	PRINT_ARRAY("COSE_Sign1 object to be signed", out->ptr, out->len);
	return ok;
}

enum err
signature_or_mac(enum sgn_or_mac_op op, bool static_dh, struct suite *suite,
		 const struct byte_array *sk, const struct byte_array *pk,
		 const struct byte_array *prk, const struct byte_array *th,
		 const struct byte_array *id_cred,
		 const struct byte_array *cred, const struct byte_array *ead,
		 enum info_label mac_label, struct byte_array *signature_or_mac)
{
	if (op == GENERATE) {
		/*we always calculate the mac*/
		TRY(mac(prk, th, id_cred, cred, ead, mac_label, static_dh,
			suite, signature_or_mac));

		if (static_dh) {
			/*signature_or_mac is mac when the caller of this function authenticates with static DH keys*/
			return ok;
		} else {
			PRINTF("SIG_STRUCT_SIZE: %d\n", SIG_STRUCT_SIZE);
			BYTE_ARRAY_NEW(sign_struct, SIG_STRUCT_SIZE,
				       th->len + 2 + COSE_SIGN1_STR_LEN +
					       id_cred->len + cred->len +
					       ead->len +
					       signature_or_mac->len +
					       ENCODING_OVERHEAD);

			TRY(signature_struct_gen(th, id_cred, cred, ead,
						 signature_or_mac,
						 &sign_struct));

			signature_or_mac->len =
				get_signature_len(suite->edhoc_sign);

			TRY(sign(suite->edhoc_sign, sk, pk, &sign_struct,
				 signature_or_mac->ptr));
			PRINT_ARRAY("signature_or_mac (is signature)",
				    signature_or_mac->ptr,
				    signature_or_mac->len);
		}
	} else { /*we verify here*/
		BYTE_ARRAY_NEW(_mac, HASH_SIZE,
			       get_hash_len(suite->edhoc_hash));

		TRY(mac(prk, th, id_cred, cred, ead, mac_label, static_dh,
			suite, &_mac));

		if (static_dh) {
			/*signature_or_mac is mac when the caller of this function authenticates with static DH keys*/

			if (0 != memcmp(_mac.ptr, signature_or_mac->ptr,
					signature_or_mac->len)) {
				return mac_authentication_failed;
			}

		} else {
			BYTE_ARRAY_NEW(signature_struct, SIG_STRUCT_SIZE,
				       th->len + 2 + COSE_SIGN1_STR_LEN +
					       id_cred->len + cred->len +
					       ead->len + _mac.len +
					       ENCODING_OVERHEAD);

			TRY(signature_struct_gen(th, id_cred, cred, ead, &_mac,
						 &signature_struct));

			bool result;
			PRINT_ARRAY("pk", pk->ptr, pk->len);
			PRINT_ARRAY("signature_struct", signature_struct.ptr,
				    signature_struct.len);
			PRINT_ARRAY("signature_or_mac", signature_or_mac->ptr,
				    signature_or_mac->len);

			TRY(verify(suite->edhoc_sign, pk,
				   (struct const_byte_array *)&signature_struct,
				   (struct const_byte_array *)signature_or_mac,
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
