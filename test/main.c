/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <zephyr.h>
#include <ztest.h>
#include "edhoc_testvector_tests/edhoc_tests.h"
#include "oscore_testvector_tests/oscore_tests.h"

static void test_initiator1(void)
{
	test_edhoc(INITIATOR, 1);
}
static void test_initiator2(void)
{
	test_edhoc(INITIATOR, 2);
}
static void test_initiator3(void)
{
	test_edhoc(INITIATOR, 3);
}
static void test_initiator4(void)
{
	test_edhoc(INITIATOR, 4);
}
static void test_initiator8(void)
{
	test_edhoc(INITIATOR, 8);
}
static void test_initiator9(void)
{
	test_edhoc(INITIATOR, 9);
}
static void test_initiator12(void)
{
	test_edhoc(INITIATOR, 12);
}
static void test_initiator13(void)
{
	test_edhoc(INITIATOR, 13);
}
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
static void test_responder1(void)
{
	test_edhoc(RESPONDER, 1);
}
static void test_responder2(void)
{
	test_edhoc(RESPONDER, 2);
}
static void test_responder3(void)
{
	test_edhoc(RESPONDER, 3);
}
static void test_responder4(void)
{
	test_edhoc(RESPONDER, 4);
}
static void test_responder8(void)
{
	test_edhoc(RESPONDER, 8);
}
static void test_responder9(void)
{
	test_edhoc(RESPONDER, 9);
}
static void test_responder12(void)
{
	test_edhoc(RESPONDER, 12);
}
static void test_responder13(void)
{
	test_edhoc(RESPONDER, 13);
}
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

void test_main(void)
{
	/* EDHOC testvector tests  */

	ztest_test_suite(initiator_tests, ztest_unit_test(test_initiator1),
			 ztest_unit_test(test_initiator2),
			 ztest_unit_test(test_initiator3),
			 ztest_unit_test(test_initiator4),
			 //ztest_unit_test(test_initiator8),
			 //ztest_unit_test(test_initiator9), for 8 and 9 suites_i should be provided in raw form!
			 ztest_unit_test(test_initiator12),
			 ztest_unit_test(test_initiator13));
	//  ztest_unit_test(test_initiator14),
	//  ztest_unit_test(test_initiator15),
	//  ztest_unit_test(test_initiator16),
	//  ztest_unit_test(test_initiator17));

	// ztest_test_suite(initiator_tests, ztest_unit_test(test_initiator1));

	ztest_test_suite(responder_tests, ztest_unit_test(test_responder1),
			 ztest_unit_test(test_responder2),
			 ztest_unit_test(test_responder3),
			 ztest_unit_test(test_responder4),
			 ztest_unit_test(test_responder8),
			 ztest_unit_test(test_responder9),
			 ztest_unit_test(test_responder12),
			 ztest_unit_test(test_responder13));
	//  ztest_unit_test(test_responder14),
	//  ztest_unit_test(test_responder15),
	//  ztest_unit_test(test_responder16),
	//  ztest_unit_test(test_responder17));

	//ztest_test_suite(responder_tests, ztest_unit_test(test_responder8));

	ztest_run_test_suite(initiator_tests);
	ztest_run_test_suite(responder_tests);

	/* OSCORE testvector tests */

	ztest_test_suite(oscore_tests, ztest_unit_test(oscore_client_test1),
			 ztest_unit_test(oscore_server_test2),
			 ztest_unit_test(oscore_client_test3),
			 ztest_unit_test(oscore_server_test4),
			 ztest_unit_test(oscore_client_test5),
			 ztest_unit_test(oscore_server_test6),
			 //test7 - not supported yet
			 ztest_unit_test(oscore_misc_test8));

	// ztest_test_suite(oscore_tests, ztest_unit_test(oscore_client_test1),
	// 		 ztest_unit_test(oscore_server_test2));

	ztest_run_test_suite(oscore_tests);
}
