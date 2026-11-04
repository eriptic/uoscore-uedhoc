/*
 * Copyright (c) 2026 Last Lock Inc.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

/*
 * EAD_4, RFC 9528 Section 5.5.
 */

#include <string.h>

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include <edhoc.h>
#include "edhoc/ciphertext.h"
#include "edhoc/suites.h"

#include "edhoc_tests.h"

void t_message_4_ead(void)
{
	/* One EAD item: label 1 and a 4-byte value. */
	uint8_t ead_4[] = { 0x01, 0x44, 0x01, 0x02, 0x03, 0x04 };
	struct byte_array ead_in = BYTE_ARRAY_INIT(ead_4, sizeof(ead_4));
	uint8_t prk_buf[32];
	uint8_t th_buf[32];
	memset(prk_buf, 0x11, sizeof(prk_buf));
	memset(th_buf, 0x22, sizeof(th_buf));
	struct byte_array prk = BYTE_ARRAY_INIT(prk_buf, sizeof(prk_buf));
	struct byte_array th = BYTE_ARRAY_INIT(th_buf, sizeof(th_buf));
	struct suite suite;
	zassert_equal(get_suite(SUITE_2, &suite), ok, "");

	uint8_t ctxt_buf[64];
	uint8_t ptxt_buf[64];
	struct byte_array ctxt = BYTE_ARRAY_INIT(ctxt_buf, sizeof(ctxt_buf));
	struct byte_array ptxt = BYTE_ARRAY_INIT(ptxt_buf, sizeof(ptxt_buf));
	zassert_equal(ciphertext_gen(CIPHERTEXT4, &suite, &NULL_ARRAY,
				     &NULL_ARRAY, &NULL_ARRAY, &ead_in, &prk,
				     &th, &ctxt, &ptxt),
		      ok, "ciphertext_gen failed");

	uint8_t ead_buf[64];
	uint8_t out_buf[64];
	struct byte_array ead_out = BYTE_ARRAY_INIT(ead_buf, sizeof(ead_buf));
	struct byte_array out = BYTE_ARRAY_INIT(out_buf, ctxt.len);
	zassert_equal(ciphertext_decrypt_split(
			      CIPHERTEXT4, &suite, NULL, &NULL_ARRAY,
			      &NULL_ARRAY, &ead_out, &prk, &th, &ctxt, &out),
		      ok, "ciphertext_decrypt_split failed");
	zassert_equal(ead_out.len, sizeof(ead_4), "EAD_4 length %u",
		      ead_out.len);
	zassert_mem_equal(ead_out.ptr, ead_4, sizeof(ead_4), "EAD_4 differs");
}
