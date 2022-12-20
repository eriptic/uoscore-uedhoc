/*
   Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <zephyr/zephyr.h>
#include <zephyr/ztest.h>

#include "common/unit_test.h"

#include "oscore.h"
#include "oscore/security_context.h"

void t500_oscore_context_init_corner_cases(void)
{
	enum err r;
	struct context c;

	/*test unsupported AEAD algorithm*/
	struct oscore_init_params params = {
		.aead_alg = 15, //15 is not supported. Only 10 is supported
	};

	r = oscore_context_init(&params, &c);
	zassert_equal(r, oscore_invalid_algorithm_aead,
		      "Error in oscore_context_init. r: %d", r);

	/*test unsupported SHA algorithm*/
	struct oscore_init_params params1 = {
		.aead_alg = 10,
		.hkdf = 15, //15 is not supported. Only 10 is supported
	};

	r = oscore_context_init(&params1, &c);
	zassert_equal(r, oscore_invalid_algorithm_hkdf,
		      "Error in oscore_context_init. r: %d", r);
}

void t501_piv2ssn(void)
{
	enum err r;
	uint64_t ssn;

	/*test with valid parameters*/
	uint8_t buf[] = { 12 };
	struct byte_array piv = BYTE_ARRAY_INIT(buf, sizeof(buf));

	r = piv2ssn(&piv, &ssn);
	zassert_equal(r, ok, "Error in piv2ssn. r: %d", r);
	zassert_equal(ssn, 12, "wrong SSN calculation");

	/*test with invalid parameters*/
	r = piv2ssn(NULL, &ssn);
	zassert_equal(r, wrong_parameter, "Error in piv2ssn. r: %d", r);
	r = piv2ssn(&piv, NULL);
	zassert_equal(r, wrong_parameter, "Error in piv2ssn. r: %d", r);
}

void t502_verify_token(void)
{
	enum err r;
	uint8_t buf[] = { 12 };
	struct byte_array cached_token = BYTE_ARRAY_INIT(buf, sizeof(buf));

	/*test with valid parameters*/
	uint8_t token[] = { 12 };
	r = verify_token(&cached_token, 1, (uint8_t *)&token);
	zassert_equal(r, ok, "Error in verify_token. r: %d", r);

	/*test with invalid parameters*/
	/*wrong token*/
	uint8_t token1[] = { 13 };
	r = verify_token(&cached_token, 1, (uint8_t *)&token1);
	zassert_equal(r, token_mismatch, "Error in verify_token. r: %d", r);
	/*wrong token len*/
	uint8_t token2[] = { 13, 14 };
	r = verify_token(&cached_token, 2, (uint8_t *)&token2);
	zassert_equal(r, token_mismatch, "Error in verify_token. r: %d", r);
}

/*
* @brief test with wrong kdf
*/
void t503_derive_corner_case(void)
{
	enum err r;
	struct common_context cc;

	uint8_t id_buf[] = { 5 };
	uint8_t id_context[] = { 5 };
	uint8_t out_buf[40];

	struct byte_array id = BYTE_ARRAY_INIT(id_buf, sizeof(id_buf));
	struct byte_array out = BYTE_ARRAY_INIT(out_buf, sizeof(out_buf));

	cc.kdf = 15;
	cc.aead_alg = 10;
	cc.id_context.ptr = id_context;
	cc.id_context.len = sizeof(id_context);

	r = derive(&cc, &id, KEY, &out);
	zassert_equal(r, oscore_unknown_hkdf, "Error in derive. r: %d", r);
}