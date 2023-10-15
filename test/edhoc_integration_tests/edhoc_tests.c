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
#include <zephyr/kernel.h>
#include <zephyr/ztest.h>

#include <edhoc.h>
#include "txrx_wrapper.h"
#include "edhoc_tests.h"
//#include "edhoc_test_vectors_v14.h"

struct messages m;

//todo check that as well that the AD are correct
int test_edhoc(enum role p, uint8_t vec_num)
{
	// rx_init();

	// m.m1_len = test_vectors[vec_num].message_1_len;
	// m.m1 = (uint8_t *)test_vectors[vec_num].message_1;
	// m.m2_len = test_vectors[vec_num].message_2_len;
	// m.m2 = (uint8_t *)test_vectors[vec_num].message_2;
	// m.m3_len = test_vectors[vec_num].message_3_len;
	// m.m3 = (uint8_t *)test_vectors[vec_num].message_3;
	// m.m4_len = test_vectors[vec_num].message_4_len;
	// m.m4 = (uint8_t *)test_vectors[vec_num].message_4;

	// if (p == INITIATOR) {
	// 	uint16_t cred_num = 1;
	// 	struct other_party_cred cred_r;
	// 	struct edhoc_initiator_context c_i;

	// 	rx_initiator_switch = true;
	// 	cred_r.id_cred.len = test_vectors[vec_num].id_cred_r_len;
	// 	cred_r.id_cred.ptr = (uint8_t *)test_vectors[vec_num].id_cred_r;
	// 	cred_r.cred.len = test_vectors[vec_num].cred_r_len;
	// 	cred_r.cred.ptr = (uint8_t *)test_vectors[vec_num].cred_r;
	// 	cred_r.g.len = test_vectors[vec_num].g_r_raw_len;
	// 	cred_r.g.ptr = (uint8_t *)test_vectors[vec_num].g_r_raw;
	// 	cred_r.pk.len = test_vectors[vec_num].pk_r_raw_len;
	// 	cred_r.pk.ptr = (uint8_t *)test_vectors[vec_num].pk_r_raw;
	// 	cred_r.ca.len = test_vectors[vec_num].ca_len;
	// 	cred_r.ca.ptr = (uint8_t *)test_vectors[vec_num].ca;
	// 	cred_r.ca_pk.len = test_vectors[vec_num].ca_pk_len;
	// 	cred_r.ca_pk.ptr = (uint8_t *)test_vectors[vec_num].ca_pk;

	// 	if (test_vectors[vec_num].c_i_raw != NULL) {
	// 		c_i.c_i.type = BSTR;
	// 		c_i.c_i.mem.c_x_bstr.len =
	// 			test_vectors[vec_num].c_i_raw_len;
	// 		c_i.c_i.mem.c_x_bstr.ptr =
	// 			(uint8_t *)test_vectors[vec_num].c_i_raw;
	// 	} else {
	// 		c_i.c_i.type = INT;
	// 		c_i.c_i.mem.c_x_int =
	// 			*test_vectors[vec_num].c_i_raw_int;
	// 	}
	// 	c_i.msg4 = true;
	// 	c_i.method = *test_vectors[vec_num].method;
	// 	c_i.suites_i.len = test_vectors[vec_num].suites_i_len;
	// 	c_i.suites_i.ptr = (uint8_t *)test_vectors[vec_num].suites_i;
	// 	c_i.ead_1.len = test_vectors[vec_num].ead_1_len;
	// 	c_i.ead_1.ptr = (uint8_t *)test_vectors[vec_num].ead_1;
	// 	c_i.ead_3.len = test_vectors[vec_num].ead_3_len;
	// 	c_i.ead_3.ptr = (uint8_t *)test_vectors[vec_num].ead_3;
	// 	c_i.id_cred_i.len = test_vectors[vec_num].id_cred_i_len;
	// 	c_i.id_cred_i.ptr = (uint8_t *)test_vectors[vec_num].id_cred_i;
	// 	c_i.cred_i.len = test_vectors[vec_num].cred_i_len;
	// 	c_i.cred_i.ptr = (uint8_t *)test_vectors[vec_num].cred_i;
	// 	c_i.g_x.len = test_vectors[vec_num].g_x_raw_len;
	// 	c_i.g_x.ptr = (uint8_t *)test_vectors[vec_num].g_x_raw;
	// 	c_i.x.len = test_vectors[vec_num].x_raw_len;
	// 	c_i.x.ptr = (uint8_t *)test_vectors[vec_num].x_raw;
	// 	c_i.g_i.len = test_vectors[vec_num].g_i_raw_len;
	// 	c_i.g_i.ptr = (uint8_t *)test_vectors[vec_num].g_i_raw;
	// 	c_i.i.len = test_vectors[vec_num].i_raw_len;
	// 	c_i.i.ptr = (uint8_t *)test_vectors[vec_num].i_raw;
	// 	c_i.sk_i.len = test_vectors[vec_num].sk_i_raw_len;
	// 	c_i.sk_i.ptr = (uint8_t *)test_vectors[vec_num].sk_i_raw;
	// 	c_i.pk_i.len = test_vectors[vec_num].pk_i_raw_len;
	// 	c_i.pk_i.ptr = (uint8_t *)test_vectors[vec_num].pk_i_raw;

	// 	err = edhoc_initiator_run(&c_i, &cred_r, cred_num, err_msg,
	// 				  &err_msg_len, ad_2, &ad_2_len, ad_4,
	// 				  &ad_4_len, PRK_4x3m, sizeof(PRK_4x3m),
	// 				  th4, sizeof(th4), tx, rx);
	// 	zassert_true(err == 0, "edhoc_initiator_run failed");

	// } else {
	// 	const uint16_t num_cred_i_elements = 1;
	// 	struct other_party_cred cred_i;
	// 	struct edhoc_responder_context c_r;

	// 	rx_initiator_switch = false;
	// 	cred_i.id_cred.len = test_vectors[vec_num].id_cred_i_len;
	// 	cred_i.id_cred.ptr = (uint8_t *)test_vectors[vec_num].id_cred_i;
	// 	cred_i.cred.len = test_vectors[vec_num].cred_i_len;
	// 	cred_i.cred.ptr = (uint8_t *)test_vectors[vec_num].cred_i;
	// 	cred_i.g.len = test_vectors[vec_num].g_i_raw_len;
	// 	cred_i.g.ptr = (uint8_t *)test_vectors[vec_num].g_i_raw;
	// 	cred_i.pk.len = test_vectors[vec_num].pk_i_raw_len;
	// 	cred_i.pk.ptr = (uint8_t *)test_vectors[vec_num].pk_i_raw;
	// 	cred_i.ca.len = test_vectors[vec_num].ca_len;
	// 	cred_i.ca.ptr = (uint8_t *)test_vectors[vec_num].ca;
	// 	cred_i.ca_pk.len = test_vectors[vec_num].ca_pk_len;
	// 	cred_i.ca_pk.ptr = (uint8_t *)test_vectors[vec_num].ca_pk;

	// 	if (test_vectors[vec_num].c_r_raw != NULL) {
	// 		c_r.c_r.type = BSTR;
	// 		c_r.c_r.mem.c_x_bstr.len =
	// 			test_vectors[vec_num].c_r_raw_len;
	// 		c_r.c_r.mem.c_x_bstr.ptr =
	// 			(uint8_t *)test_vectors[vec_num].c_r_raw;
	// 	} else {
	// 		c_r.c_r.type = INT;
	// 		c_r.c_r.mem.c_x_int =
	// 			*test_vectors[vec_num].c_r_raw_int;
	// 	}
	// 	c_r.msg4 = true; /*we allways test message 4 */
	// 	c_r.suites_r.len = test_vectors[vec_num].suites_r_len;
	// 	c_r.suites_r.ptr = (uint8_t *)test_vectors[vec_num].suites_r;

	// 	c_r.ead_2.len = test_vectors[vec_num].ead_2_len;
	// 	c_r.ead_2.ptr = (uint8_t *)test_vectors[vec_num].ead_2;

	// 	c_r.ead_4.len = test_vectors[vec_num].ead_4_len;
	// 	c_r.ead_4.ptr = (uint8_t *)test_vectors[vec_num].ead_4;

	// 	c_r.id_cred_r.len = test_vectors[vec_num].id_cred_r_len;
	// 	c_r.id_cred_r.ptr = (uint8_t *)test_vectors[vec_num].id_cred_r;

	// 	c_r.cred_r.len = test_vectors[vec_num].cred_r_len;
	// 	c_r.cred_r.ptr = (uint8_t *)test_vectors[vec_num].cred_r;

	// 	c_r.g_y.len = test_vectors[vec_num].g_y_raw_len;
	// 	c_r.g_y.ptr = (uint8_t *)test_vectors[vec_num].g_y_raw;

	// 	c_r.y.len = test_vectors[vec_num].y_raw_len;
	// 	c_r.y.ptr = (uint8_t *)test_vectors[vec_num].y_raw;

	// 	c_r.g_r.len = test_vectors[vec_num].g_r_raw_len;
	// 	c_r.g_r.ptr = (uint8_t *)test_vectors[vec_num].g_r_raw;

	// 	c_r.r.len = test_vectors[vec_num].r_raw_len;
	// 	c_r.r.ptr = (uint8_t *)test_vectors[vec_num].r_raw;

	// 	c_r.sk_r.len = test_vectors[vec_num].sk_r_raw_len;
	// 	c_r.sk_r.ptr = (uint8_t *)test_vectors[vec_num].sk_r_raw;

	// 	c_r.pk_r.len = test_vectors[vec_num].pk_r_raw_len;
	// 	c_r.pk_r.ptr = (uint8_t *)test_vectors[vec_num].pk_r_raw;

	// 	err = edhoc_responder_run(&c_r, &cred_i, num_cred_i_elements,
	// 				  err_msg, &err_msg_len,
	// 				  (uint8_t *)&ad_1, &ad_1_len,
	// 				  (uint8_t *)&ad_3, &ad_3_len, PRK_4x3m,
	// 				  sizeof(PRK_4x3m), th4, sizeof(th4),
	// 				  tx, rx);
	// 	zassert_true(err == 0, "edhoc_responder_run failed");
	// }

	// // err = edhoc_exporter(SHA_256, PRK_4x3m, sizeof(PRK_4x3m), th4,
	// // 		     sizeof(th4), "OSCORE_Master_Secret",
	// // 		     oscore_master_secret, 16);

	// // zassert_true(err == 0, "edhoc_exporter failed");

	// // err = edhoc_exporter(SHA_256, PRK_4x3m, sizeof(PRK_4x3m), th4,
	// // 		     sizeof(th4), "OSCORE_Master_Salt",
	// // 		     oscore_master_salt, 8);

	// // zassert_true(err == 0, "edhoc_exporter failed");

	// /* check th4, PRK_4x3m, OSCORE Master secret and salt are correct */
	// zassert_mem_equal__(&PRK_4x3m, test_vectors[vec_num].prk_4x3m_raw,
	// 		    sizeof(PRK_4x3m), "wrong PRK_4x3m");

	// zassert_mem_equal__(&th4, test_vectors[vec_num].th_4_raw, sizeof(th4),
	// 		    "wrong TH4");

	// zassert_mem_equal__(&oscore_master_secret,
	// 		    test_vectors[vec_num].oscore_secret_raw,
	// 		    sizeof(oscore_master_secret),
	// 		    "wrong OSCORE Master Secret");

	// zassert_mem_equal__(&oscore_master_salt,
	// 		    test_vectors[vec_num].oscore_salt_raw,
	// 		    sizeof(oscore_master_salt),
	// 		    "wrong OSCORE Master Salt");
	return 0;
}
