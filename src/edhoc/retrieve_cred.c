/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <string.h>

#include "edhoc/cert.h"
#include "edhoc/bstr_encode_decode.h"
#include "edhoc/retrieve_cred.h"

#include "common/crypto_wrapper.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"
#include "common/memcpy_s.h"

#include "cbor/edhoc_decode_id_cred_x.h"

/**
 * @brief 			Verifies a certificate and copies it to the cred 
 * 				buffer. It also extracts the public key
 * 				contained in the certificate. 
 * 
 * @param static_dh_auth 	Type of the key contained in the certificate -- 
 * 				signature key or static DH key.
 * @param cred_array 		array containing credentials.
 * @param label 		CBOR map label of id_cred_x.
 * @param[in] cert 		The certificate.
 * @param[in] cred 		Cred buffer.
 * @param[in] pk 		Public key.
 * @param[in] g 		Static DH public key.
 * @return 			Ok or error code
 */
static inline enum err
verify_cert2cred(bool static_dh_auth, struct cred_array *cred_array,
		 enum id_cred_x_label label, struct const_byte_array *cert,
		 struct byte_array *cred, struct byte_array *pk,
		 struct byte_array *g)
{
	PRINT_ARRAY("ID_CRED_x contains a certificate", cert->ptr, cert->len);
	TRY(encode_bstr((struct byte_array *)cert, cred));

	bool verified = false;
	switch (label) {
	/* for now we transfer a single certificate, therefore bag and chain are the same */
	case x5bag:
	case x5chain:
		if (static_dh_auth) {
			pk->len = 0;
			TRY(cert_x509_verify(cert, cred_array, g, &verified));
		} else {
			g->len = 0;
			TRY(cert_x509_verify(cert, cred_array, pk, &verified));
		}
		break;
	case c5b:
	case c5c:
		if (static_dh_auth) {
			pk->len = 0;
			TRY(cert_c509_verify(cert, cred_array, g, &verified));
		} else {
			g->len = 0;
			TRY(cert_c509_verify(cert, cred_array, pk, &verified));
		}
		break;
		break;

	default:
		break;
	}

	if (verified) {
		PRINT_MSG("Certificate verification successful!\n");
		return ok;
	} else {
		return certificate_authentication_failed;
	}
	return ok;
}

/**
 * @brief 			Get the local cred object.
 * 
 * @param static_dh_auth 	True if static DH is used for authentication.
 * @param[in] cred_array 	An array of trust anchors
 * @param[in] ID_cred 		The ID of the actual credential.
 * @param[out] cred 		The retrievd credentials	
 * @param[out] pk 		The retrievd signature authentication public key
 * @param[out] g 		The retrievd static DH authentication public key
 * @return 			Ok or error code
 */
static enum err get_local_cred(bool static_dh_auth,
			       struct cred_array *cred_array,
			       struct byte_array *ID_cred,
			       struct byte_array *cred, struct byte_array *pk,
			       struct byte_array *g)
{
	for (uint32_t i = 0; i < cred_array->len; i++) {
		if ((cred_array->ptr[i].id_cred.len == ID_cred->len) &&
		    (0 == memcmp(cred_array->ptr[i].id_cred.ptr, ID_cred->ptr,
				 ID_cred->len))) {
			/*retrieve CRED_x*/
			TRY(_memcpy_s(cred->ptr, cred->len,
				      cred_array->ptr[i].cred.ptr,
				      cred_array->ptr[i].cred.len));
			cred->len = cred_array->ptr[i].cred.len;

			/*retrieve PK*/
			if (static_dh_auth) {
				pk->len = 0;
				if (cred_array->ptr[i].g.len == 65) {
					/*decompressed P256 DH pk*/
					g->ptr[0] = 0x2;
					TRY(_memcpy_s(
						&g->ptr[1], g->len - 1,
						&cred_array->ptr[i].g.ptr[1],
						32));
					g->len = 33;

				} else {
					TRY(_memcpy_s(g->ptr, g->len,
						      cred_array->ptr[i].g.ptr,
						      cred_array->ptr[i].g.len));
					g->len = cred_array->ptr[i].g.len;
				}

			} else {
				g->len = 0;
				TRY(_memcpy_s(pk->ptr, pk->len,
					      cred_array->ptr[i].pk.ptr,
					      cred_array->ptr[i].pk.len));
				pk->len = cred_array->ptr[i].pk.len;
			}
			return ok;
		}
	}

	return credential_not_found;
}

enum err retrieve_cred(bool static_dh_auth, struct cred_array *cred_array,
		       struct byte_array *id_cred, struct byte_array *cred,
		       struct byte_array *pk, struct byte_array *g)
{
	size_t decode_len = 0;
	struct id_cred_x_map map = { 0 };

	TRY_EXPECT(cbor_decode_id_cred_x_map(id_cred->ptr, id_cred->len, &map,
					     &decode_len),
		   0);
	/*the cred should be locally available on the device if 
	kid, x5u, x5t, c5u, c5t is used*/
	if (map.id_cred_x_map_kid_present || map.id_cred_x_map_x5u_present ||
	    map.id_cred_x_map_x5t_present || map.id_cred_x_map_c5u_present ||
	    map.id_cred_x_map_c5t_present) {
		TRY(get_local_cred(static_dh_auth, cred_array, id_cred, cred,
				   pk, g));
		return ok;
	}
	/*x5chain*/
	else if (map.id_cred_x_map_x5chain_present) {
		struct const_byte_array cert = BYTE_ARRAY_INIT(
			map.id_cred_x_map_x5chain.id_cred_x_map_x5chain.value,
			(uint32_t)map.id_cred_x_map_x5chain
				.id_cred_x_map_x5chain.len);

		TRY(verify_cert2cred(static_dh_auth, cred_array, x5chain, &cert,
				     cred, pk, g));
		return ok;
	}
	/*x5bag*/
	else if (map.id_cred_x_map_x5bag_present) {
		struct const_byte_array cert = BYTE_ARRAY_INIT(
			map.id_cred_x_map_x5bag.id_cred_x_map_x5bag.value,
			(uint32_t)map.id_cred_x_map_x5bag.id_cred_x_map_x5bag
				.len);
		TRY(verify_cert2cred(static_dh_auth, cred_array, x5bag, &cert,
				     cred, pk, g));
		return ok;
	}
	/*c5c*/
	else if (map.id_cred_x_map_c5c_present) {
		struct const_byte_array cert = BYTE_ARRAY_INIT(
			map.id_cred_x_map_c5c.id_cred_x_map_c5c.value,
			(uint32_t)map.id_cred_x_map_c5c.id_cred_x_map_c5c.len);
		TRY(verify_cert2cred(static_dh_auth, cred_array, c5c, &cert,
				     cred, pk, g));
		return ok;
	}
	/*c5b*/
	else if (map.id_cred_x_map_c5b_present) {
		struct const_byte_array cert = BYTE_ARRAY_INIT(
			map.id_cred_x_map_c5b.id_cred_x_map_c5b.value,
			(uint32_t)map.id_cred_x_map_c5b.id_cred_x_map_c5b.len);
		TRY(verify_cert2cred(static_dh_auth, cred_array, c5b, &cert,
				     cred, pk, g));
		return ok;
	}

	return credential_not_found;
}
