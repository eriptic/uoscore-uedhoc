/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <zephyr/kernel.h>
#include <zephyr/ztest.h>
#include "edhoc_integration_tests/edhoc_tests.h"
#include "oscore_tests.h"

ZTEST_SUITE(uoscore_uedhoc, NULL, NULL, NULL, NULL, NULL);

ZTEST(uoscore_uedhoc, test_edhoc_exporter)
{
	test_exporter();
};

ZTEST(uoscore_uedhoc, test_initiator_responder_interaction)
{
	test_initiator_responder_interaction(1);
	test_initiator_responder_interaction(2);
};

ZTEST(uoscore_uedhoc, test_oscore)
{
	t1_oscore_client_request_response();
	t2_oscore_server_request_response();
	t3_oscore_client_request();
	t4_oscore_server_key_derivation();
	t5_oscore_client_request();
	t6_oscore_server_key_derivation();
	t8_oscore_server_response_simple_ack();
	t9_oscore_client_server_observe();
	t10_oscore_client_server_after_reboot();
	t100_inner_outer_option_split__no_special_options();
	t101_inner_outer_option_split__with_observe_notification();
	t102_inner_outer_option_split__with_observe_registration();
	t103_oscore_pkg_generate__request_with_observe_registration();
	t104_oscore_pkg_generate__request_with_observe_notification();
	t105_inner_outer_option_split__too_many_options();
	t106_oscore_option_generate_no_piv();
	t200_options_serialize_deserialize();
	t201_coap_serialize_deserialize();
	t202_options_deserialize_corner_cases();
	t300_oscore_option_parser_no_piv();
	t301_oscore_option_parser_wrong_n();
	t302_oscore_option_parser_no_kid();
	t303_options_reorder();
	t400_is_class_e();
	t401_cache_echo_val();
	t402_echo_val_is_fresh();
	t500_oscore_context_init_corner_cases();
	t501_piv2ssn();
	t502_ssn2piv();
	t503_derive_corner_case();
	t600_server_replay_init_test();
	t601_server_replay_reinit_test();
	t602_server_replay_check_at_start_test();
	t603_server_replay_check_in_progress_test();
	t604_server_replay_insert_zero_test();
	t605_server_replay_insert_test();
	t606_server_replay_standard_scenario_test();
};
