/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef OSCORE_TESTS_H
#define OSCORE_TESTS_H

/*integration tests*/
void t1_oscore_client_request_response(void);
void t3_oscore_client_request(void);
void t5_oscore_client_request(void);
void t2_oscore_server_request_response(void);
void t4_oscore_server_key_derivation(void);
void t6_oscore_server_key_derivation(void);
void t8_oscore_server_response_simple_ack(void);
void t9_oscore_client_server_observe(void);
void t10_oscore_client_server_after_reboot(void);
void t11_oscore_ssn_overflow_protection(void);

/*unit tests*/
void t100_inner_outer_option_split__no_special_options(void);
void t101_inner_outer_option_split__with_observe_notification(void);
void t102_inner_outer_option_split__with_observe_registration(void);
void t103_oscore_pkg_generate__request_with_observe_registration(void);
void t104_oscore_pkg_generate__request_with_observe_notification(void);
void t105_inner_outer_option_split__too_many_options(void);
void t106_oscore_option_generate_no_piv(void);

void t200_options_serialize_deserialize(void);
void t201_coap_serialize_deserialize(void);
void t202_options_deserialize_corner_cases(void);
void t203_coap_get_message_type(void);

void t300_oscore_option_parser_no_piv(void);
void t301_oscore_option_parser_wrong_n(void);
void t302_oscore_option_parser_no_kid(void);
void t303_options_reorder(void);

void t400_is_class_e(void);
void t401_cache_echo_val(void);
void t402_echo_val_is_fresh(void);
void t403_uri_path_create(void);
void t404_get_observe_value(void);

void t500_oscore_context_init_corner_cases(void);
void t501_piv2ssn(void);
void t502_ssn2piv(void);
void t503_derive_corner_case(void);
void t504_context_freshness(void);

void t600_server_replay_init_test(void);
void t601_server_replay_reinit_test(void);
void t602_server_replay_check_at_start_test(void);
void t603_server_replay_check_in_progress_test(void);
void t604_server_replay_insert_zero_test(void);
void t605_server_replay_insert_test(void);
void t606_server_replay_standard_scenario_test(void);

void t700_interactions_init_test(void);
void t701_interactions_set_record_test(void);
void t702_interactions_get_record_test(void);
void t703_interactions_remove_record_test(void);
void t704_interactions_usecases_test(void);

void t800_oscore_latency_test(void);
#endif