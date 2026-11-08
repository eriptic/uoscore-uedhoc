/*
 * Copyright (c) 2026 SmartWireless GmbH & Co. KG.
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

/*
 * Representation of a 'kid' in ID_CRED_x, RFC 9528 Section 3.3.2 and
 * Section 3.5.3.2.
 */

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include <edhoc.h>
#include "edhoc/plaintext.h"
#include "edhoc/retrieve_cred.h"

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

#define ARRAY(...) ((const uint8_t[]){ __VA_ARGS__ })

/* SGN_or_MAC_3 as a bstr, appended to the ID_CRED_I under test */
#define MAC_3 0x48, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08

static void check_id_cred2kid(const uint8_t *id_cred, uint32_t id_cred_len,
			      const uint8_t *exp, uint32_t exp_len)
{
	uint8_t kid_buf[8];
	struct byte_array kid = { .ptr = kid_buf, .len = sizeof(kid_buf) };
	struct byte_array in = { .ptr = (uint8_t *)id_cred,
				 .len = id_cred_len };

	zassert_equal(id_cred2kid(&in, &kid), ok, "id_cred2kid failed");
	zassert_equal(kid.len, exp_len, "wrong kid length");
	zassert_mem_equal__(kid.ptr, exp, exp_len, "wrong kid");
}

void t_kid_id_cred2kid(void)
{
	/* kid that is a 1-byte CBOR int encoding: sent as int */
	check_id_cred2kid(ARRAY(0xa1, 0x04, 0x41, 0x32), 4, ARRAY(0x32), 1);
	check_id_cred2kid(ARRAY(0xa1, 0x04, 0x41, 0x05), 4, ARRAY(0x05), 1);
	check_id_cred2kid(ARRAY(0xa1, 0x04, 0x41, 0x37), 4, ARRAY(0x37), 1);

	/* any other kid: sent as bstr */
	check_id_cred2kid(ARRAY(0xa1, 0x04, 0x41, 0x18), 4, ARRAY(0x41, 0x18),
			  2);
	check_id_cred2kid(ARRAY(0xa1, 0x04, 0x41, 0x38), 4, ARRAY(0x41, 0x38),
			  2);
	check_id_cred2kid(ARRAY(0xa1, 0x04, 0x42, 0x01, 0x02), 5,
			  ARRAY(0x42, 0x01, 0x02), 3);

	/* kid as int, as in drafts before RFC 9528 */
	check_id_cred2kid(ARRAY(0xa1, 0x04, 0x32), 3, ARRAY(0x32), 1);

	/* a map the decoder does not know: no compact encoding */
	check_id_cred2kid(ARRAY(0xa1, 0x18, 0x21, 0x82, 0x41, 0x01, 0x41, 0x02),
			  8, NULL, 0);
	check_id_cred2kid(ARRAY(0xa1, 0x0e, 0xa1, 0x02, 0x60), 5, NULL, 0);

	/* kid together with another parameter: no compact encoding */
	check_id_cred2kid(ARRAY(0xa2, 0x04, 0x41, 0x05, 0x18, 0x22, 0x82, 0x2e,
				0x42, 0x01, 0x02),
			  11, NULL, 0);
}

static void check_plaintext3(const uint8_t *ptxt, uint32_t ptxt_len,
			     const uint8_t *exp, uint32_t exp_len)
{
	uint8_t id_cred_buf[16];
	uint8_t mac_buf[16];
	uint8_t ead_buf[1];
	struct byte_array in = { .ptr = (uint8_t *)ptxt, .len = ptxt_len };
	struct byte_array id_cred = { .ptr = id_cred_buf,
				      .len = sizeof(id_cred_buf) };
	struct byte_array mac = { .ptr = mac_buf, .len = sizeof(mac_buf) };
	struct byte_array ead = { .ptr = ead_buf, .len = sizeof(ead_buf) };

	zassert_equal(plaintext_split(&in, NULL, &id_cred, &mac, &ead), ok,
		      "plaintext_split failed");
	zassert_equal(id_cred.len, exp_len, "wrong ID_CRED_I length");
	zassert_mem_equal__(id_cred.ptr, exp, exp_len, "wrong ID_CRED_I");
	zassert_equal(mac.len, 8, "wrong MAC_3 length");
}

void t_kid_plaintext_split(void)
{
	/* int -12 stands for the kid h'2b' */
	check_plaintext3(ARRAY(0x2b, MAC_3), 10, ARRAY(0xa1, 0x04, 0x41, 0x2b),
			 4);
	/* int 5 stands for the kid h'05' */
	check_plaintext3(ARRAY(0x05, MAC_3), 10, ARRAY(0xa1, 0x04, 0x41, 0x05),
			 4);
	/* kid sent as bstr */
	check_plaintext3(ARRAY(0x41, 0x18, MAC_3), 11,
			 ARRAY(0xa1, 0x04, 0x41, 0x18), 4);
	check_plaintext3(ARRAY(0x42, 0x01, 0x02, MAC_3), 12,
			 ARRAY(0xa1, 0x04, 0x42, 0x01, 0x02), 5);
	/* int outside -24..23, only sent by peers before RFC 9528 */
	check_plaintext3(ARRAY(0x18, 0x20, MAC_3), 11,
			 ARRAY(0xa1, 0x04, 0x18, 0x20), 4);
}

static enum err split_map(const uint8_t *ptxt, uint32_t ptxt_len, bool has_c_r,
			  const uint8_t *exp, uint32_t exp_len)
{
	uint8_t c_r_buf[1];
	uint8_t id_cred_buf[256];
	uint8_t mac_buf[16];
	uint8_t ead_buf[1];
	struct byte_array in = { .ptr = (uint8_t *)ptxt, .len = ptxt_len };
	struct byte_array c_r = { .ptr = c_r_buf, .len = sizeof(c_r_buf) };
	struct byte_array id_cred = { .ptr = id_cred_buf,
				      .len = sizeof(id_cred_buf) };
	struct byte_array mac = { .ptr = mac_buf, .len = sizeof(mac_buf) };
	struct byte_array ead = { .ptr = ead_buf, .len = sizeof(ead_buf) };
	enum err r = plaintext_split(&in, has_c_r ? &c_r : NULL, &id_cred, &mac,
				     &ead);

	if (r == ok) {
		zassert_equal(id_cred.len, exp_len, "wrong ID_CRED_x length");
		zassert_mem_equal__(id_cred.ptr, exp, exp_len,
				    "wrong ID_CRED_x");
		zassert_equal(mac.len, 8, "wrong MAC length");
	}
	return r;
}

void t_id_cred_map_plaintext_split(void)
{
	/* x5chain with two certificates */
	zassert_equal(
		split_map(ARRAY(0xa1, 0x18, 0x21, 0x82, 0x41, 0x01, 0x41, 0x02,
				MAC_3),
			  17, false,
			  ARRAY(0xa1, 0x18, 0x21, 0x82, 0x41, 0x01, 0x41, 0x02),
			  8),
		ok, "x5chain array");
	/* the same with C_R in front */
	zassert_equal(
		split_map(ARRAY(0x27, 0xa1, 0x18, 0x21, 0x82, 0x41, 0x01, 0x41,
				0x02, MAC_3),
			  18, true,
			  ARRAY(0xa1, 0x18, 0x21, 0x82, 0x41, 0x01, 0x41, 0x02),
			  8),
		ok, "x5chain array after C_R");
	/* kccs, an unknown label */
	zassert_equal(split_map(ARRAY(0xa1, 0x0e, 0xa1, 0x02, 0x60, MAC_3), 14,
				false, ARRAY(0xa1, 0x0e, 0xa1, 0x02, 0x60), 5),
		      ok, "kccs");
	/* x5t with a text string algorithm, which is not re-encoded */
	zassert_equal(
		split_map(ARRAY(0xa1, 0x18, 0x22, 0x82, 0x61, 0x61, 0x41, 0x01,
				MAC_3),
			  17, false,
			  ARRAY(0xa1, 0x18, 0x22, 0x82, 0x61, 0x61, 0x41, 0x01),
			  8),
		ok, "x5t with tstr algorithm");

	/* a string or an array that does not fit in the plaintext */
	zassert_not_equal(split_map(ARRAY(0xa1, 0x18, 0x21, 0x43, 0x01), 5,
				    false, NULL, 0),
			  ok, "truncated string");
	zassert_not_equal(split_map(ARRAY(0xa1, 0x18, 0x21, 0x98, 0x20, 0x01),
				    6, false, NULL, 0),
			  ok, "truncated array");
	/* an indefinite length map */
	zassert_not_equal(split_map(ARRAY(0xbf, 0xff, MAC_3), 11, false, NULL,
				    0),
			  ok, "indefinite length map");
}

void t_id_cred_map_nesting(void)
{
	/* { 0 : [[[...]]] }, nested as deep as a large message allows */
	static uint8_t ptxt[1024];
	static uint8_t mac[] = { MAC_3 };
	uint32_t depth = sizeof(ptxt) - sizeof(mac) - 3;

	ptxt[0] = 0xa1;
	ptxt[1] = 0x00;
	memset(&ptxt[2], 0x81, depth);
	ptxt[2 + depth] = 0x00;
	memcpy(&ptxt[3 + depth], mac, sizeof(mac));

	/* Too long for ID_CRED_x, but it must not exhaust the stack */
	zassert_equal(split_map(ptxt, sizeof(ptxt), false, NULL, 0),
		      buffer_to_small, "deeply nested map");
}

static enum err lookup(const uint8_t *configured, uint32_t configured_len,
		       struct byte_array *id_cred)
{
	static const uint8_t cred_x[] = { 0xa0 };
	static const uint8_t g_x[32] = { 0x01 };
	uint8_t cred_buf[8];
	uint8_t pk_buf[65];
	uint8_t g_buf[65];
	struct byte_array cred = { .ptr = cred_buf, .len = sizeof(cred_buf) };
	struct byte_array pk = { .ptr = pk_buf, .len = sizeof(pk_buf) };
	struct byte_array g = { .ptr = g_buf, .len = sizeof(g_buf) };

	struct other_party_cred other = {
		.id_cred = { .ptr = (uint8_t *)configured,
			     .len = configured_len },
		.cred = { .ptr = (uint8_t *)cred_x, .len = sizeof(cred_x) },
		.g = { .ptr = (uint8_t *)g_x, .len = sizeof(g_x) },
	};
	struct cred_array creds = { .len = 1, .ptr = &other };

	return retrieve_cred(true, &creds, id_cred, &cred, &pk, &g);
}

void t_kid_retrieve_cred(void)
{
	uint8_t buf[4];
	struct byte_array id_cred = { .ptr = buf, .len = sizeof(buf) };
	const uint8_t received[] = { 0xa1, 0x04, 0x41, 0x32 };

	/* credential configured as in RFC 9528 */
	memcpy(buf, received, sizeof(received));
	id_cred.len = sizeof(received);
	zassert_equal(lookup(received, sizeof(received), &id_cred), ok,
		      "RFC 9528 kid not found");
	zassert_equal(id_cred.len, 4, "ID_CRED changed");

	/* credential configured with the int kid of drafts before RFC 9528 */
	id_cred.len = sizeof(received);
	zassert_equal(lookup(ARRAY(0xa1, 0x04, 0x32), 3, &id_cred), ok,
		      "int kid not found");
	zassert_equal(id_cred.len, 3, "ID_CRED not replaced");
	zassert_mem_equal__(id_cred.ptr, ARRAY(0xa1, 0x04, 0x32), 3,
			    "ID_CRED not replaced");

	/* different kid */
	memcpy(buf, received, sizeof(received));
	id_cred.len = sizeof(received);
	zassert_equal(lookup(ARRAY(0xa1, 0x04, 0x41, 0x33), 4, &id_cred),
		      credential_not_found, "wrong credential found");

	/* kid h'18' isn't an int encoding, so no int fallback */
	buf[3] = 0x18;
	id_cred.len = sizeof(received);
	zassert_equal(lookup(ARRAY(0xa1, 0x04, 0x18, 0x18), 4, &id_cred),
		      credential_not_found, "wrong credential found");
}

void t_retrieve_cred_uncompressed_g(void)
{
	static const uint8_t id_cred_x[] = { 0xa1, 0x04, 0x41, 0x2b };
	static const uint8_t cred_x[] = { 0xa0 };
	uint8_t g_x[65] = { 0x04 };
	uint8_t cred_buf[8];
	uint8_t pk_buf[65];
	uint8_t g_buf[65];
	uint8_t id_cred_buf[sizeof(id_cred_x)];
	struct byte_array cred = { .ptr = cred_buf, .len = sizeof(cred_buf) };
	struct byte_array pk = { .ptr = pk_buf, .len = sizeof(pk_buf) };
	struct byte_array g = { .ptr = g_buf, .len = sizeof(g_buf) };
	struct byte_array id_cred = { .ptr = id_cred_buf,
				      .len = sizeof(id_cred_buf) };

	for (uint32_t i = 1; i < sizeof(g_x); i++) {
		g_x[i] = (uint8_t)i;
	}
	memcpy(id_cred_buf, id_cred_x, sizeof(id_cred_x));

	struct other_party_cred other = {
		.id_cred = { .ptr = (uint8_t *)id_cred_x,
			     .len = sizeof(id_cred_x) },
		.cred = { .ptr = (uint8_t *)cred_x, .len = sizeof(cred_x) },
		.g = { .ptr = g_x, .len = sizeof(g_x) },
	};
	struct cred_array creds = { .len = 1, .ptr = &other };

	zassert_equal(retrieve_cred(true, &creds, &id_cred, &cred, &pk, &g), ok,
		      "credential not found");
	zassert_equal(g.len, 32, "wrong G_X length");
	zassert_mem_equal__(g.ptr, &g_x[1], 32, "wrong G_X");
}
