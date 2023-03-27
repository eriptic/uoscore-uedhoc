/*
   Copyright (c) 2022 Assa Abloy. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#include <stdio.h>
#include <string.h>
#include <zephyr/ztest.h>

#include "oscore/replay_protection.h"

#define WINDOW_SIZE OSCORE_SERVER_REPLAY_WINDOW_SIZE
#define DUMMY_BYTE 10
#define WINDOW_SIZE_BYTES (WINDOW_SIZE * sizeof(uint64_t))

static struct server_replay_window_t replay_window;

static void _copy_window(struct server_replay_window_t *dest,
			 const struct server_replay_window_t *src)
{
	memcpy(dest, src, sizeof(struct server_replay_window_t));
}

static void _compare_windows(struct server_replay_window_t *current,
			     const struct server_replay_window_t *expected)
{
	zassert_mem_equal(current->window, expected->window, WINDOW_SIZE_BYTES,
			  "");
	zassert_equal(current->seq_num_zero_received,
		      expected->seq_num_zero_received, "");
}

static void
_update_window_and_check_result(uint64_t seq_num,
				struct server_replay_window_t *replay_window,
				bool expected_result)
{
	bool result = server_replay_window_update(seq_num, replay_window);
	zassert_equal(expected_result, result, "");
}

static void
_validate_window_and_check_result(uint64_t seq_num,
				  struct server_replay_window_t *replay_window,
				  bool expected_result)
{
	bool result = server_is_sequence_number_valid(seq_num, replay_window);
	zassert_equal(expected_result, result, "");
}

/**
 * @brief Test replay window initialization.
 */
void t600_server_replay_init_test(void)
{
	static struct server_replay_window_t compare_window = { 0 };

	/* set random data to all fields */
	memset(replay_window.window, DUMMY_BYTE, WINDOW_SIZE_BYTES);
	replay_window.seq_num_zero_received = true;

	enum err result;
	result = server_replay_window_init(NULL);
	zassert_equal(wrong_parameter, result, "");

	result = server_replay_window_init(&replay_window);
	zassert_equal(ok, result, "");
	_compare_windows(&replay_window, &compare_window);

	/* extra check of helper function */
	zassert_equal(false, server_is_sequence_number_valid(0, NULL), "");
}

/**
 * @brief Test replay window re-initialization.
 */
void t601_server_replay_reinit_test(void)
{
	static const struct server_replay_window_t compare_window_1 = {
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5, 6 },
		true
	};

	static const struct server_replay_window_t compare_window_2 = {
		{ 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
		  111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
		  122, 123, 124, 125, 126, 127, 128, 129, 130, 131 },
		true
	};

	enum err result;
	result = server_replay_window_reinit(6, NULL);
	zassert_equal(wrong_parameter, result, "");

	result = server_replay_window_reinit(6, &replay_window);
	zassert_equal(ok, result, "");
	_compare_windows(&replay_window, &compare_window_1);

	result = server_replay_window_reinit(131, &replay_window);
	zassert_equal(ok, result, "");
	_compare_windows(&replay_window, &compare_window_2);
}

/**
 * @brief Test replay window check for various sequence numbers - this case represents beginning of the communication.
 */
void t602_server_replay_check_at_start_test(void)
{
	// missing Sequence Numbers in starting_point: 9, 5, 3, 2, 1, 0
	// SN 11 is ahead of current window = OK
	// SN 12 might be received before SN 11 = also OK
	// SN 10 is received in the last message = NOT OK
	// SN 9 is delayed and not received yet = OK
	// SN 8 is already received = NOT OK
	// SN 5 is delayed = OK
	// SN 0 is delayed and still in the window range = OK

	static const struct server_replay_window_t starting_point = {
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 6, 7, 8, 10 },
		false
	};

	static const uint64_t numbers_to_check[] = { 11, 12, 10, 9, 8, 5, 0 };
	static const bool numbers_results[] = { true,  true, false, true,
						false, true, true };
	const uint16_t check_count =
		sizeof(numbers_to_check) / sizeof(numbers_to_check[0]);

	_copy_window(&replay_window, &starting_point);

	for (uint16_t index = 0; index < check_count; index++) {
		bool result_valid = numbers_results[index];
		uint64_t seq_num = numbers_to_check[index];
		_validate_window_and_check_result(seq_num, &replay_window,
						  result_valid);
	}
}

/**
 * @brief Test replay window check for various sequence numbers - this case represents communication in progress.
 */
void t603_server_replay_check_in_progress_test(void)
{
	// missing Sequence Numbers in starting_point: 126, 127, 133
	// SN 99 and below are behind the window = NOT OK

	static const struct server_replay_window_t starting_point = {
		{ 100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110,
		  111, 112, 113, 114, 115, 116, 117, 118, 119, 120, 121,
		  122, 123, 124, 125, 128, 129, 130, 131, 132, 134 },
		true
	};

	static const uint64_t numbers_to_check[] = { 135, 134, 133, 132,
						     127, 126, 99,  80 };
	static const bool numbers_results[] = { true, false, true,  false,
						true, true,  false, false };
	const uint16_t check_count =
		sizeof(numbers_to_check) / sizeof(numbers_to_check[0]);

	_copy_window(&replay_window, &starting_point);

	for (uint16_t index = 0; index < check_count; index++) {
		bool result_valid = numbers_results[index];
		uint64_t seq_num = numbers_to_check[index];
		_validate_window_and_check_result(seq_num, &replay_window,
						  result_valid);
	}
}

/**
 * @brief Test inserting zero into replay window at different moments of the session.
 */
void t604_server_replay_insert_zero_test(void)
{
	static const struct server_replay_window_t compare_window_1 = { { 0 }, true };

	static const struct server_replay_window_t compare_window_2 = {
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1 },
		true
	};

	server_replay_window_init(&replay_window);

	/* First, check if sequence number 0 at the beginning of the session doesn't break anything. */
	/* After inserting 0, window should still be empty, but zero received flag should be true. */
	_update_window_and_check_result(0, &replay_window, true);
	_compare_windows(&replay_window, &compare_window_1);

	/* Inserting 0 for the second time should result in error. */
	_update_window_and_check_result(0, &replay_window, false);

	/* Inserting valid number should be ok. */
	_update_window_and_check_result(1, &replay_window, true);
	_compare_windows(&replay_window, &compare_window_2);

	/* Reset replay window and insert SeqNum=1. Later, inserting delayed SeqNum=0 should still be ok. */
	server_replay_window_init(&replay_window);
	_update_window_and_check_result(1, &replay_window, true);
	_update_window_and_check_result(0, &replay_window, true);
	_compare_windows(&replay_window, &compare_window_2);

	/* Reset replay window and test immunity to simple replay attack using SeqNum=0. */
	server_replay_window_init(&replay_window);
	_update_window_and_check_result(0, &replay_window, true);
	_update_window_and_check_result(1, &replay_window, true);
	_update_window_and_check_result(0, &replay_window, false);
	_compare_windows(&replay_window, &compare_window_2);

	/* Reset replay window and insert multiple values that will roll the window. Later, inserting delayed SeqNum=0 should fail. */
	server_replay_window_init(&replay_window);
	for (uint64_t seq_num = 1; seq_num <= 50; seq_num++) {
		_update_window_and_check_result(seq_num, &replay_window, true);
	}
	_update_window_and_check_result(0, &replay_window, false);
}

/**
 * @brief Test inserting values into replay window at different moments of the session.
 */
void t605_server_replay_insert_test(void)
{
	static const struct server_replay_window_t starting_point = {
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 6, 7, 8, 10 },
		false
	};
	static const struct server_replay_window_t compare_window_1 = {
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 6, 7, 8, 10 },
		false
	};
	static const struct server_replay_window_t compare_window_2 = {
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 5, 6, 7, 8, 10 },
		false
	};
	static const struct server_replay_window_t compare_window_3 = {
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 5, 6, 7, 8, 9, 10 },
		false
	};
	static const struct server_replay_window_t compare_window_4 = {
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,	0,
		  0, 0, 0, 0, 0, 0, 0, 1, 4, 5, 6, 7, 8, 9, 10, 12 },
		false
	};
	static const struct server_replay_window_t compare_window_5 = {
		{ 69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79,
		  80, 81, 82, 83, 84, 85, 86, 87, 88, 89, 90,
		  91, 92, 93, 94, 95, 96, 97, 98, 99, 100 },
		false
	};

	_copy_window(&replay_window, &starting_point);

	_update_window_and_check_result(1, &replay_window, true);
	_compare_windows(&replay_window, &compare_window_1);

	_update_window_and_check_result(5, &replay_window, true);
	_compare_windows(&replay_window, &compare_window_2);

	_update_window_and_check_result(9, &replay_window, true);
	_compare_windows(&replay_window, &compare_window_3);

	_update_window_and_check_result(12, &replay_window, true);
	_compare_windows(&replay_window, &compare_window_4);

	for (uint64_t seq_num = 13; seq_num <= 100; seq_num++) {
		_update_window_and_check_result(seq_num, &replay_window, true);
	}
	_compare_windows(&replay_window, &compare_window_5);
}

/**
 * @brief Standard scenario test - checks and updates
 */
void t606_server_replay_standard_scenario_test(void)
{
	static const struct server_replay_window_t compare_window_1 = {
		{ 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
		  0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5 },
		true
	};

	static const struct server_replay_window_t compare_window_2 = {
		{ 19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29,
		  30, 31, 32, 33, 34, 35, 36, 37, 38, 39, 40,
		  41, 42, 43, 44, 45, 46, 47, 48, 49, 50 },
		true
	};

	static const uint64_t incoming_numbers[] = { 1, 0, 4, 4, 2, 3, 5, 1, 0 };
	static const enum err check_results[] = { true,	 true,	true,
						  false, true,	true,
						  true,	 false, false };
	uint16_t const check_count =
		sizeof(incoming_numbers) / sizeof(incoming_numbers[0]);

	server_replay_window_init(&replay_window);

	//several messages are out of order or repeated
	for (uint16_t index = 0; index < check_count; index++) {
		bool result_valid = check_results[index];
		uint64_t seq_num = incoming_numbers[index];
		_validate_window_and_check_result(seq_num, &replay_window,
						  result_valid);

		if (result_valid) {
			//replay check OK - after MAC verification, window can be updated
			_update_window_and_check_result(seq_num, &replay_window,
							true);
		}
	}
	_compare_windows(&replay_window, &compare_window_1);

	//proper reception of multiple messages, to make sure that in real scenario window can do its job
	for (uint64_t seq_num = 10; seq_num <= 50; seq_num++) {
		_validate_window_and_check_result(seq_num, &replay_window,
						  true);
		_update_window_and_check_result(seq_num, &replay_window, true);
	}
	_compare_windows(&replay_window, &compare_window_2);
}
