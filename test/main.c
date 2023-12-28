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

#define TEST_EDHOC_EXPORTER 1
#define TEST_INITIATOR_RESPONDER_INTERACTION1 2
#define TEST_INITIATOR_RESPONDER_INTERACTION2 3
#define T1_OSCORE_CLIENT_REQUEST_RESPONSE 4
#define T2_OSCORE_SERVER_REQUEST_RESPONSE 5
#define T3_OSCORE_CLIENT_REQUEST 6
#define T4_OSCORE_SERVER_KEY_DERIVATION 7
#define T5_OSCORE_CLIENT_REQUEST 8
#define T6_OSCORE_SERVER_KEY_DERIVATION 9
#define T8_OSCORE_SERVER_RESPONSE_SIMPLE_ACK 10
#define T9_OSCORE_CLIENT_SERVER_OBSERVE 11
#define T10_OSCORE_CLIENT_SERVER_AFTER_REBOOT 12
#define T100_INNER_OUTER_OPTION_SPLIT__NO_SPECIAL_OPTIONS 13
#define T101_INNER_OUTER_OPTION_SPLIT__WITH_OBSERVE_NOTIFICATION 14
#define T102_INNER_OUTER_OPTION_SPLIT__WITH_OBSERVE_REGISTRATION 15
#define T103_OSCORE_PKG_GENERATE__REQUEST_WITH_OBSERVE_REGISTRATION 16
#define T104_OSCORE_PKG_GENERATE__REQUEST_WITH_OBSERVE_NOTIFICATION 17
#define T105_INNER_OUTER_OPTION_SPLIT__TOO_MANY_OPTIONS 18
#define T106_OSCORE_OPTION_GENERATE_NO_PIV 19
#define T200_OPTIONS_SERIALIZE_DESERIALIZE 20
#define T201_COAP_SERIALIZE_DESERIALIZE 21
#define T202_OPTIONS_DESERIALIZE_CORNER_CASES 22
#define T300_OSCORE_OPTION_PARSER_NO_PIV 23
#define T301_OSCORE_OPTION_PARSER_WRONG_N 24
#define T302_OSCORE_OPTION_PARSER_NO_KID 25
#define T303_OPTIONS_REORDER 26
#define T400_IS_CLASS_E 27
#define T401_CACHE_ECHO_VAL 28
#define T402_ECHO_VAL_IS_FRESH 29
#define T500_OSCORE_CONTEXT_INIT_CORNER_CASES 30
#define T501_PIV2SSN 31
#define T502_SSN2PIV 32
#define T503_DERIVE_CORNER_CASE 33
#define T600_SERVER_REPLAY_INIT_TEST 34
#define T601_SERVER_REPLAY_REINIT_TEST 35
#define T602_SERVER_REPLAY_CHECK_AT_START_TEST 36
#define T603_SERVER_REPLAY_CHECK_IN_PROGRESS_TEST 37
#define T604_SERVER_REPLAY_INSERT_ZERO_TEST 38
#define T605_SERVER_REPLAY_INSERT_TEST 39
#define T606_SERVER_REPLAY_STANDARD_SCENARIO_TEST 40
#define T800_OSCORE_LATENCY_TEST 41

// if this macro is defined all tests will be executed
#define EXECUTE_ALL_TESTS

// in order to execute only a specific tes set this macro to a specific
// test macro and comment out EXECUTE_ALL_TESTS
#define EXECUTE_ONLY_TEST T800_OSCORE_LATENCY_TEST

/**
 * @brief       This function allows to skip a given test if only one other test 
 *              needs to be executed.
 * 
 * @param test_name_macro 
 */
static void skip(int test_name_macro, void (*test_function)())
{
#if !defined EXECUTE_ALL_TESTS
	if (EXECUTE_ONLY_TEST == test_name_macro) {
		test_function();
	} else {
		ztest_test_skip();
	}
#else
	test_function();
#endif
}

ZTEST_SUITE(uoscore_uedhoc, NULL, NULL, NULL, NULL, NULL);

ZTEST(uoscore_uedhoc, test_edhoc_exporter)
{
	skip(TEST_EDHOC_EXPORTER, test_exporter);
};

ZTEST(uoscore_uedhoc, test_initiator_responder_interaction1)
{
	skip(TEST_INITIATOR_RESPONDER_INTERACTION1,
	     t_initiator_responder_interaction1);
};

ZTEST(uoscore_uedhoc, test_initiator_responder_interaction2)
{
	skip(TEST_INITIATOR_RESPONDER_INTERACTION2,
	     t_initiator_responder_interaction2);
};

ZTEST(uoscore_uedhoc, t1_oscore)
{
	skip(T1_OSCORE_CLIENT_REQUEST_RESPONSE,
	     t1_oscore_client_request_response);
}

ZTEST(uoscore_uedhoc, t2_oscore)
{
	skip(T2_OSCORE_SERVER_REQUEST_RESPONSE,
	     t2_oscore_server_request_response);
}

ZTEST(uoscore_uedhoc, t3_oscore)
{
	skip(T3_OSCORE_CLIENT_REQUEST, t3_oscore_client_request);
}

ZTEST(uoscore_uedhoc, t4_oscore)
{
	skip(T4_OSCORE_SERVER_KEY_DERIVATION, t4_oscore_server_key_derivation);
}

ZTEST(uoscore_uedhoc, t5_oscore)
{
	skip(T5_OSCORE_CLIENT_REQUEST, t5_oscore_client_request);
}

ZTEST(uoscore_uedhoc, t6_oscore)
{
	skip(T6_OSCORE_SERVER_KEY_DERIVATION, t6_oscore_server_key_derivation);
}

ZTEST(uoscore_uedhoc, t8_oscore)
{
	skip(T8_OSCORE_SERVER_RESPONSE_SIMPLE_ACK,
	     t8_oscore_server_response_simple_ack);
}

ZTEST(uoscore_uedhoc, t9_oscore)
{
	skip(T9_OSCORE_CLIENT_SERVER_OBSERVE, t9_oscore_client_server_observe);
}

ZTEST(uoscore_uedhoc, t10_oscore)
{
	skip(T10_OSCORE_CLIENT_SERVER_AFTER_REBOOT,
	     t10_oscore_client_server_after_reboot);
}

ZTEST(uoscore_uedhoc, t100_oscore)
{
	skip(T100_INNER_OUTER_OPTION_SPLIT__NO_SPECIAL_OPTIONS,
	     t100_inner_outer_option_split__no_special_options);
}

ZTEST(uoscore_uedhoc, t101_oscore)
{
	skip(T101_INNER_OUTER_OPTION_SPLIT__WITH_OBSERVE_NOTIFICATION,
	     t101_inner_outer_option_split__with_observe_notification);
}

ZTEST(uoscore_uedhoc, t102_oscore)
{
	skip(T102_INNER_OUTER_OPTION_SPLIT__WITH_OBSERVE_REGISTRATION,
	     t102_inner_outer_option_split__with_observe_registration);
}

ZTEST(uoscore_uedhoc, t103_oscore)
{
	skip(T103_OSCORE_PKG_GENERATE__REQUEST_WITH_OBSERVE_REGISTRATION,
	     t103_oscore_pkg_generate__request_with_observe_registration);
}

ZTEST(uoscore_uedhoc, t104_oscore)
{
	skip(T104_OSCORE_PKG_GENERATE__REQUEST_WITH_OBSERVE_NOTIFICATION,
	     t104_oscore_pkg_generate__request_with_observe_notification);
}

ZTEST(uoscore_uedhoc, t105_oscore)
{
	skip(T105_INNER_OUTER_OPTION_SPLIT__TOO_MANY_OPTIONS,
	     t105_inner_outer_option_split__too_many_options);
}

ZTEST(uoscore_uedhoc, t106_oscore)
{
	skip(T106_OSCORE_OPTION_GENERATE_NO_PIV,
	     t106_oscore_option_generate_no_piv);
}

ZTEST(uoscore_uedhoc, t200_oscore)
{
	skip(T200_OPTIONS_SERIALIZE_DESERIALIZE,
	     t200_options_serialize_deserialize);
}

ZTEST(uoscore_uedhoc, t201_oscore)
{
	skip(T201_COAP_SERIALIZE_DESERIALIZE, t201_coap_serialize_deserialize);
}

ZTEST(uoscore_uedhoc, t202_oscore)
{
	skip(T202_OPTIONS_DESERIALIZE_CORNER_CASES,
	     t202_options_deserialize_corner_cases);
}

ZTEST(uoscore_uedhoc, t300_oscore)
{
	skip(T300_OSCORE_OPTION_PARSER_NO_PIV,
	     t300_oscore_option_parser_no_piv);
}

ZTEST(uoscore_uedhoc, t301_oscore)
{
	skip(T301_OSCORE_OPTION_PARSER_WRONG_N,
	     t301_oscore_option_parser_wrong_n);
}

ZTEST(uoscore_uedhoc, t302_oscore)
{
	skip(T302_OSCORE_OPTION_PARSER_NO_KID,
	     t302_oscore_option_parser_no_kid);
}

ZTEST(uoscore_uedhoc, t303_oscore)
{
	skip(T303_OPTIONS_REORDER, t303_options_reorder);
}

ZTEST(uoscore_uedhoc, t400_oscore)
{
	skip(T400_IS_CLASS_E, t400_is_class_e);
}

ZTEST(uoscore_uedhoc, t401_oscore)
{
	skip(T401_CACHE_ECHO_VAL, t401_cache_echo_val);
}

ZTEST(uoscore_uedhoc, t402_oscore)
{
	skip(T402_ECHO_VAL_IS_FRESH, t402_echo_val_is_fresh);
}

ZTEST(uoscore_uedhoc, t500_oscore)
{
	skip(T500_OSCORE_CONTEXT_INIT_CORNER_CASES,
	     t500_oscore_context_init_corner_cases);
}

ZTEST(uoscore_uedhoc, t501_oscore)
{
	skip(T501_PIV2SSN, t501_piv2ssn);
}

ZTEST(uoscore_uedhoc, t502_oscore)
{
	skip(T502_SSN2PIV, t502_ssn2piv);
}

ZTEST(uoscore_uedhoc, t503_oscore)
{
	skip(T503_DERIVE_CORNER_CASE, t503_derive_corner_case);
}

ZTEST(uoscore_uedhoc, t600_oscore)
{
	skip(T600_SERVER_REPLAY_INIT_TEST, t600_server_replay_init_test);
}

ZTEST(uoscore_uedhoc, t601_oscore)
{
	skip(T601_SERVER_REPLAY_REINIT_TEST, t601_server_replay_reinit_test);
}

ZTEST(uoscore_uedhoc, t602_oscore)
{
	skip(T602_SERVER_REPLAY_CHECK_AT_START_TEST,
	     t602_server_replay_check_at_start_test);
}

ZTEST(uoscore_uedhoc, t603_oscore)
{
	skip(T603_SERVER_REPLAY_CHECK_IN_PROGRESS_TEST,
	     t603_server_replay_check_in_progress_test);
}

ZTEST(uoscore_uedhoc, t604_oscore)
{
	skip(T604_SERVER_REPLAY_INSERT_ZERO_TEST,
	     t604_server_replay_insert_zero_test);
}

ZTEST(uoscore_uedhoc, t605_oscore)
{
	skip(T605_SERVER_REPLAY_INSERT_TEST, t605_server_replay_insert_test);
}

ZTEST(uoscore_uedhoc, t606_oscore)
{
	skip(T606_SERVER_REPLAY_STANDARD_SCENARIO_TEST,
	     t606_server_replay_standard_scenario_test);
}



/*
 * In order to measure the latency of coap2oscore, oscore2coap, 
 * edhoc_responder_run, edhoc_initiator_run you need one of the supported boards 
 * by Zephyr OS, see https://docs.zephyrproject.org/latest/boards/index.html
 * Make sure that MEASURE_LATENCY_ON is enabled in CMakeLists.txt
 * Build flash the test project for your board e.g.,
 * west build -b=nrf9160dk_nrf9160; west flash.
 * make also sure that DEBUG_PRINT is disabled
 */
#ifdef MEASURE_LATENCY_ON
ZTEST(uoscore_uedhoc, t800_oscore)
{
	skip(T800_OSCORE_LATENCY_TEST, t800_oscore_latency_test);
}
#endif /*MEASURE_LATENCY_ON*/