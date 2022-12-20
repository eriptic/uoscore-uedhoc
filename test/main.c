/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <zephyr/zephyr.h>
#include <zephyr/ztest.h>
#include "edhoc_integration_tests/edhoc_tests.h"
#include "oscore_tests.h"
#include "oscore_unit_tests/replay_protection_tests.h"

// static void test_initiator1(void)
// {
// 	test_edhoc(INITIATOR, 1);
// }
// static void test_initiator2(void)
// {
// 	test_edhoc(INITIATOR, 2);
// }
// static void test_initiator3(void)
// {
// 	test_edhoc(INITIATOR, 3);
// }
// static void test_initiator4(void)
// {
// 	test_edhoc(INITIATOR, 4);
// }
// static void test_initiator8(void)
// {
// 	test_edhoc(INITIATOR, 8);
// }
// static void test_initiator9(void)
// {
// 	test_edhoc(INITIATOR, 9);
// }
// static void test_initiator12(void)
// {
// 	test_edhoc(INITIATOR, 12);
// }
// static void test_initiator13(void)
// {
// 	test_edhoc(INITIATOR, 13);
// }
// static void test_initiator14(void)
// {
// 	test_edhoc(INITIATOR, 14);
// }
// static void test_initiator15(void)
// {
// 	test_edhoc(INITIATOR, 15);
// }
// static void test_initiator16(void)
// {
// 	test_edhoc(INITIATOR, 16);
// }
// static void test_initiator17(void)
// {
// 	test_edhoc(INITIATOR, 17);
// }
/********************************/
// static void test_responder1(void)
// {
// 	test_edhoc(RESPONDER, 1);
// }
// static void test_responder2(void)
// {
// 	test_edhoc(RESPONDER, 2);
// }
// static void test_responder3(void)
// {
// 	test_edhoc(RESPONDER, 3);
// }
// static void test_responder4(void)
// {
// 	test_edhoc(RESPONDER, 4);
// }
// static void test_responder8(void)
// {
// 	test_edhoc(RESPONDER, 8);
// }
// static void test_responder9(void)
// {
// 	test_edhoc(RESPONDER, 9);
// }
// static void test_responder12(void)
// {
// 	test_edhoc(RESPONDER, 12);
// }
// static void test_responder13(void)
// {
// 	test_edhoc(RESPONDER, 13);
// }
// static void test_responder14(void)
// {
// 	test_edhoc(RESPONDER, 14);
// }
// static void test_responder15(void)
// {
// 	test_edhoc(RESPONDER, 15);
// }
// static void test_responder16(void)
// {
// 	test_edhoc(RESPONDER, 16);
// }
// static void test_responder17(void)
// {
// 	test_edhoc(RESPONDER, 17);
// }

static void test_initiator_responder_interaction1(void)
{
	test_initiator_responder_interaction(1);
}

static void test_initiator_responder_interaction2(void)
{
	test_initiator_responder_interaction(2);
}

void test_main(void)
{
	/* EDHOC testvector tests  */

	ztest_test_suite(exporter, ztest_unit_test(test_exporter));
	ztest_test_suite(
		initiator_responder_interaction,
		ztest_unit_test(test_initiator_responder_interaction1),
		ztest_unit_test(test_initiator_responder_interaction2));

	/* OSCORE test-vector tests */

	// ztest_test_suite(
	// 	oscore_tests,
	// 	ztest_unit_test(
	// 		t105_inner_outer_option_split__too_many_options));
	ztest_test_suite(
		oscore_tests,
		ztest_unit_test(t1_oscore_client_request_response),
		ztest_unit_test(t2_oscore_server_request_response),
		ztest_unit_test(t3_oscore_client_request),
		ztest_unit_test(t4_oscore_server_key_derivation),
		ztest_unit_test(t5_oscore_client_request),
		ztest_unit_test(t6_oscore_server_key_derivation),
		ztest_unit_test(t8_oscore_server_response_simple_ack),
		ztest_unit_test(t9_oscore_client_server_observe),
		ztest_unit_test(t10_oscore_client_server_after_reboot),
		ztest_unit_test(
			t100_inner_outer_option_split__no_special_options),
		ztest_unit_test(
			t101_inner_outer_option_split__with_observe_notification),
		ztest_unit_test(
			t102_inner_outer_option_split__with_observe_registration),
		ztest_unit_test(
			t103_oscore_pkg_generate__request_with_observe_registration),
		ztest_unit_test(
			t104_oscore_pkg_generate__request_with_observe_notification),
		ztest_unit_test(
			t105_inner_outer_option_split__too_many_options),
		ztest_unit_test(t106_oscore_option_generate_no_piv),
		ztest_unit_test(t200_options_serialize_deserialize),
		ztest_unit_test(t201_coap_serialize_deserialize),
		ztest_unit_test(t202_options_deserialize_corner_cases),
		ztest_unit_test(t300_oscore_option_parser_no_piv),
		ztest_unit_test(t301_oscore_option_parser_wrong_n),
		ztest_unit_test(t302_oscore_option_parser_no_kid),
		ztest_unit_test(t303_options_reorder),
		ztest_unit_test(t400_is_class_e),
		ztest_unit_test(t401_cache_echo_val),
		ztest_unit_test(t402_echo_val_is_fresh));

	ztest_run_test_suite(exporter);
	ztest_run_test_suite(initiator_responder_interaction);
	run_replay_protection_tests();
	ztest_run_test_suite(oscore_tests);
}
