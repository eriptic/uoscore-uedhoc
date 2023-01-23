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
#include <string.h>

#include "oscore/nonce.h"
#include "oscore/security_context.h"

#include "common/print_util.h"
#include "common/memcpy_s.h"

enum err create_nonce(struct byte_array *id_piv, struct byte_array *piv,
		      struct byte_array *common_iv, struct byte_array *nonce)
{
	/* "1. left-padding the PIV in network byte order with zeroes to exactly 5 bytes"*/
	uint8_t padded_piv[MAX_PIV_LEN] = { 0 };
	TRY(_memcpy_s(&padded_piv[sizeof(padded_piv) - piv->len], piv->len,
		      piv->ptr, piv->len));

	/* "2. left-padding the ID_PIV in network byte order with zeroes to exactly nonce length minus 6 bytes," */

	uint8_t padded_id_piv[NONCE_LEN - MAX_PIV_LEN - 1] = { 0 };
	const uint8_t padded_id_piv_len = sizeof(padded_id_piv);
	TRY(_memcpy_s(&padded_id_piv[sizeof(padded_id_piv) - id_piv->len],
		      id_piv->len, id_piv->ptr, id_piv->len));

	/* "3. concatenating the size of the ID_PIV (a single byte S) with the padded ID_PIV and the padded PIV,"*/
	nonce->ptr[0] = (uint8_t)id_piv->len;
	TRY(_memcpy_s(&nonce->ptr[1], padded_id_piv_len, padded_id_piv,
		      padded_id_piv_len));

	TRY(_memcpy_s(&nonce->ptr[1 + sizeof(padded_id_piv)],
		      sizeof(padded_piv), padded_piv, sizeof(padded_piv)));

	PRINT_ARRAY("nonce input A", nonce->ptr, nonce->len);
	PRINT_ARRAY("nonce input B", common_iv->ptr, common_iv->len);
	/* "4. and then XORing with the Common IV."*/
	for (uint32_t i = 0; i < common_iv->len; i++) {
		nonce->ptr[i] ^= common_iv->ptr[i];
	}

	PRINT_ARRAY("nonce", nonce->ptr, nonce->len);
	return ok;
}
