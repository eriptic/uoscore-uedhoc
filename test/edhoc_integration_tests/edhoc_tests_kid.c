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
