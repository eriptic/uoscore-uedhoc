/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdio.h>

#include "oscore.h"

#include "oscore/oscore_cose.h"
#include "oscore/security_context.h"

#include "common/crypto_wrapper.h"
#include "common/memcpy_s.h"
#include "common/print_util.h"

#include "cbor/oscore_enc_structure.h"

/*the additional bytes in the enc_structure are constant*/
#define ENCRYPT0_ENCODING_OVERHEAD 16

/**
 * @brief Encode the input AAD to defined COSE structure
 * @param external_aad: input aad to form COSE structure
 * @param out: output encoded COSE byte string
 * @return err
 */
static enum err create_enc_structure(struct byte_array *external_aad,
				     struct byte_array *out)
{
	struct oscore_enc_structure enc_structure;

	uint8_t context[] = { "Encrypt0" };
	enc_structure.oscore_enc_structure_context.value = context;
	enc_structure.oscore_enc_structure_context.len =
		(uint32_t)strlen((char *)context);
	enc_structure.oscore_enc_structure_protected.value = NULL;
	enc_structure.oscore_enc_structure_protected.len = 0;
	enc_structure.oscore_enc_structure_external_aad.value =
		external_aad->ptr;
	enc_structure.oscore_enc_structure_external_aad.len =
		external_aad->len;

	size_t payload_len_out = 0;

	TRY_EXPECT(cbor_encode_oscore_enc_structure(out->ptr, out->len,
						    &enc_structure,
						    &payload_len_out),
		   0);

	out->len = (uint32_t)payload_len_out;
	return ok;
}

enum err oscore_cose_decrypt(struct byte_array *in_ciphertext,
			     struct byte_array *out_plaintext,
			     struct byte_array *nonce,
			     struct byte_array *recipient_aad,
			     struct byte_array *key)
{
	/* get enc_structure */
	uint32_t aad_len = recipient_aad->len + ENCRYPT0_ENCODING_OVERHEAD;
	BYTE_ARRAY_NEW(aad, MAX_AAD_LEN, aad_len);
	TRY(create_enc_structure(recipient_aad, &aad));
	PRINT_ARRAY("AAD encoded", aad.ptr, aad.len);
	struct byte_array tag = BYTE_ARRAY_INIT(
		(in_ciphertext->ptr + in_ciphertext->len - 8), 8);

	PRINT_ARRAY("Ciphertext", in_ciphertext->ptr, in_ciphertext->len);

	TRY(aead(DECRYPT, in_ciphertext, key, nonce, &aad, out_plaintext,
		 &tag));

	PRINT_ARRAY("Decrypted plaintext", out_plaintext->ptr,
		    out_plaintext->len);
	return ok;
}

enum err oscore_cose_encrypt(struct byte_array *in_plaintext,
			     struct byte_array *out_ciphertext,
			     struct byte_array *nonce,
			     struct byte_array *sender_aad,
			     struct byte_array *key)
{
	/* get enc_structure  */
	uint32_t aad_len = sender_aad->len + ENCRYPT0_ENCODING_OVERHEAD;
	BYTE_ARRAY_NEW(aad, MAX_AAD_LEN, aad_len);

	TRY(create_enc_structure(sender_aad, &aad));
	PRINT_ARRAY("aad enc structure", aad.ptr, aad.len);

	struct byte_array tag =
		BYTE_ARRAY_INIT(out_ciphertext->ptr + in_plaintext->len, 8);

	out_ciphertext->len -= tag.len;
	TRY(aead(ENCRYPT, in_plaintext, key, nonce, &aad, out_ciphertext,
		 &tag));

	PRINT_ARRAY("tag", tag.ptr, tag.len);
	PRINT_ARRAY("Ciphertext", out_ciphertext->ptr, out_ciphertext->len);
	out_ciphertext->len += tag.len;
	PRINT_ARRAY("Ciphertext + tag", out_ciphertext->ptr,
		    out_ciphertext->len);

	return ok;
}
