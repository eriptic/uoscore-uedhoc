/*
   Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include "common/unit_test.h"

#include "oscore.h"
#include "oscore/security_context.h"

static void test_single_piv2ssn(uint8_t *piv_ptr, uint32_t piv_size, uint64_t expected_ssn)
{
	uint64_t ssn;
	struct byte_array piv = BYTE_ARRAY_INIT(piv_ptr, piv_size);
	enum err result = piv2ssn(&piv, &ssn);
	zassert_equal(result, ok, "Error in piv2ssn (code=%d)", result);
	zassert_equal(ssn, expected_ssn, "wrong SSN calculation");
}

static void test_single_ssn2piv(uint64_t ssn, uint8_t *expected_piv, uint32_t expected_size)
{
	static uint8_t buf[5];
	struct byte_array piv = BYTE_ARRAY_INIT(buf, sizeof(buf));
	enum err result = ssn2piv(ssn, &piv);

	zassert_equal(result, ok, "Error in ssn2piv (code=%d)", result);
	zassert_equal(piv.len, expected_size, "wrong PIV size");
	zassert_mem_equal(piv.ptr, expected_piv, expected_size, "wrong PIV value");
}

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
	uint8_t piv1[] = { 0x00 };
	uint8_t piv2[] = { 0xFF };
	uint8_t piv3[] = { 0x02, 0xF0 };
	uint8_t piv4[] = { 0xDE, 0xAD, 0xBE, 0xEF };
	uint8_t piv5[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	/*test with valid parameters*/
	test_single_piv2ssn(piv1, sizeof(piv1), 0x00);
	test_single_piv2ssn(piv2, sizeof(piv2), 0xFF);
	test_single_piv2ssn(piv3, sizeof(piv3), 0x02F0);
	test_single_piv2ssn(piv4, sizeof(piv4), 0xDEADBEEF);
	test_single_piv2ssn(piv5, sizeof(piv5), MAX_PIV_FIELD_VALUE);
	test_single_piv2ssn(NULL, 0, 0);
	test_single_piv2ssn(NULL, 1, 0);

	/*test with invalid parameters*/
	r = piv2ssn(NULL, &ssn);
	zassert_equal(r, wrong_parameter, "Error in piv2ssn. r: %d", r); //nullpointer for input value

	struct byte_array piv_ba1 = BYTE_ARRAY_INIT(piv1, sizeof(piv1));
	r = piv2ssn(&piv_ba1, NULL);
	zassert_equal(r, wrong_parameter, "Error in piv2ssn. r: %d", r); //nullpointer for output value

	struct byte_array piv_ba2 = BYTE_ARRAY_INIT(piv1, 10);
	r = piv2ssn(&piv_ba2, &ssn);
	zassert_equal(r, wrong_parameter, "Error in piv2ssn. r: %d", r); //buffer size exceeds maximum
}

void t502_ssn2piv(void)
{
	enum err r;
	uint8_t piv1[] = { 0x00 };
	uint8_t piv2[] = { 0x20 };
	uint8_t piv3[] = { 0x20, 0xAA };
	uint8_t piv4[] = { 0xDE, 0xAD, 0xBE, 0xEF };
	uint8_t piv5[] = { 0xFF, 0xFF, 0xFF, 0xFF, 0xFF };

	/*test with valid parameters*/
	test_single_ssn2piv(0, piv1, sizeof(piv1));
	test_single_ssn2piv(0x20, piv2, sizeof(piv2));
	test_single_ssn2piv(0x20AA, piv3, sizeof(piv3));
	test_single_ssn2piv(0xDEADBEEF, piv4, sizeof(piv4));
	test_single_ssn2piv(MAX_PIV_FIELD_VALUE, piv5, sizeof(piv5));

	/*test with invalid parameters*/
	r = ssn2piv(0, NULL);
	zassert_equal(r, wrong_parameter, "Error in piv2ssn. r: %d", r); //nullpointer for input value

	struct byte_array piv_ba1 = BYTE_ARRAY_INIT(NULL, 10);
	r = ssn2piv(0, &piv_ba1);
	zassert_equal(r, wrong_parameter, "Error in piv2ssn. r: %d", r); //nullpointer for input value

	struct byte_array piv_ba2 = BYTE_ARRAY_INIT(piv5, sizeof(piv5));
	r = ssn2piv(MAX_PIV_FIELD_VALUE + 1, &piv_ba2);
	zassert_equal(r, wrong_parameter, "Error in piv2ssn. r: %d", r); //max value of ssn exceeded
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

/**
 * @brief Test catching the SSN overflow event.
 * 
 */
void t504_context_freshness(void)
{
	enum err result;
	struct context security_context;

	result = check_context_freshness(NULL);
	zassert_equal(result, wrong_parameter, "");

	security_context.sc.ssn = 100;
	result = check_context_freshness(&security_context);
	zassert_equal(result, ok, "");

	/* mimic reaching final value of SSN */
	security_context.sc.ssn = OSCORE_SSN_OVERFLOW_VALUE;
	result = check_context_freshness(&security_context);
	zassert_equal(result, oscore_ssn_overflow, "");
}
