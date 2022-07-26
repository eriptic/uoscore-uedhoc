
#include <stdio.h>
#include <string.h>
#include <ztest.h>

#include "oscore/replay_protection.h"


#define WINDOW_SIZE         32
#define DUMMY_BYTE          10


/**
 * @brief Test replay window initialization.
 */
static void server_replay_init_test(void)
{
    enum err result;
    static uint64_t test_window[WINDOW_SIZE];
    static uint64_t compare_window[WINDOW_SIZE];

    uint16_t size = WINDOW_SIZE * sizeof(compare_window[0]);
    memset(test_window, DUMMY_BYTE, size);
    memset(compare_window, 0, size);

    result = server_replay_window_init(NULL, WINDOW_SIZE);
    zassert_equal(wrong_parameter, result, "");

    result = server_replay_window_init(test_window, 0);
    zassert_equal(wrong_parameter, result, "");

    result = server_replay_window_init(test_window, WINDOW_SIZE);
    zassert_equal(ok, result, "");
    zassert_mem_equal(test_window, compare_window, size, "");
}


/**
 * @brief Test replay window check for various sequence numbers - this case represents beginning of the communication.
 */
static void server_replay_beginning_test(void)
{
    // missing Sequence Numbers in test_window: 9, 5, 3, 2, 1
    // SN 11 is ahead of current window = OK
    // SN 12 might be received before SN 11 = also OK
    // SN 10 is received in the last message = NOT OK
    // SN 9 is delayed and not received yet = OK
    // SN 8 is already received = NOT OK

    static uint64_t test_window[WINDOW_SIZE] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 6, 7, 8, 10
        };

    static uint64_t numbers_to_check[] = {11, 12, 10, 9, 8, 5, 0};
    static bool numbers_results[] = {true, true, false, true, false, true, false};
    uint16_t check_count = sizeof(numbers_to_check) / sizeof(numbers_to_check[0]);

    for (uint16_t index = 0; index < check_count; index++)
    {
        bool result_valid = numbers_results[index];
        bool result = server_is_sequence_number_valid(numbers_to_check[index], test_window, WINDOW_SIZE);
        zassert_equal(result_valid, result, "");
    }
}


/**
 * @brief Test replay window check for various sequence numbers - this case represents communication in progress.
 */
static void server_replay_in_progress_test(void)
{
    // missing Sequence Numbers in test_window: 126, 127, 133
    // SN 99 and below are behind the window = NOT OK

    static uint64_t test_window[WINDOW_SIZE] = {
        100, 101, 102, 103, 104, 105, 106, 107, 108, 109, 110, 111, 112, 113, 114, 115,
        116, 117, 118, 119, 120, 121, 122, 123, 124, 125, 128, 129, 130, 131, 132, 134
        };

    static uint64_t numbers_to_check[] = {135, 134, 133, 132, 127, 126, 99, 80};
    static bool numbers_results[] = {true, false, true, false, true, true, false, false};
    uint16_t check_count = sizeof(numbers_to_check) / sizeof(numbers_to_check[0]);

    for (uint16_t index = 0; index < check_count; index++)
    {
        bool result_valid = numbers_results[index];
        bool result = server_is_sequence_number_valid(numbers_to_check[index], test_window, WINDOW_SIZE);
        zassert_equal(result_valid, result, "");
    }
}


/**
 * @brief Test inserting values into replay window.
 */
static void server_replay_insert_test(void)
{
    static uint64_t test_window[WINDOW_SIZE] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 4, 6, 7, 8, 10
        };
    static uint64_t compare_window_1[WINDOW_SIZE] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 6, 7, 8, 10
        };
    static uint64_t compare_window_2[WINDOW_SIZE] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 5, 6, 7, 8, 10
        };
    static uint64_t compare_window_3[WINDOW_SIZE] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 1, 4, 5, 6, 7, 8, 9, 10
        };
    static uint64_t compare_window_4[WINDOW_SIZE] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 1, 4, 5, 6, 7, 8, 9, 10, 12
        };
    static uint64_t compare_window_5[WINDOW_SIZE] = {
        69, 70, 71, 72, 73, 74, 75, 76, 77, 78, 79, 80, 81, 82, 83, 84,
        85, 86, 87, 88, 89, 90, 91, 92, 93, 94, 95, 96, 97, 98, 99, 100
        };
    uint16_t size = WINDOW_SIZE * sizeof(test_window[0]);

    server_replay_window_update(1, test_window, WINDOW_SIZE);
    zassert_mem_equal(test_window, compare_window_1, size, "");

    server_replay_window_update(5, test_window, WINDOW_SIZE);
    zassert_mem_equal(test_window, compare_window_2, size, "");

    server_replay_window_update(9, test_window, WINDOW_SIZE);
    zassert_mem_equal(test_window, compare_window_3, size, "");

    server_replay_window_update(12, test_window, WINDOW_SIZE);
    zassert_mem_equal(test_window, compare_window_4, size, "");

    for (uint64_t seq_num = 13; seq_num <= 100; seq_num++)
    {
        server_replay_window_update(seq_num, test_window, WINDOW_SIZE);
    }
    zassert_mem_equal(test_window, compare_window_5, size, "");
}


/**
 * @brief Standard scenario test - checks and updates
 */
static void server_replay_standard_scenario_test(void)
{
    static uint64_t test_window[WINDOW_SIZE];
    static uint64_t compare_window_1[WINDOW_SIZE] = {
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,
        0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1, 2, 3, 4, 5
        };
    static uint64_t compare_window_2[WINDOW_SIZE] = {
        19, 20, 21, 22, 23, 24, 25, 26, 27, 28, 29, 30, 31, 32, 33, 34,
        35, 36, 37, 38, 39, 40, 41, 42, 43, 44, 45, 46, 47, 48, 49, 50
        };
    uint16_t size = WINDOW_SIZE * sizeof(test_window[0]);

    static uint64_t incoming_numbers[] = {1, 4, 4, 2, 3, 5, 1, 0};
    static enum err check_results[] = {true, true, false, true, true, true, false, false};
    uint16_t check_count = sizeof(incoming_numbers) / sizeof(incoming_numbers[0]);

    server_replay_window_init(test_window, WINDOW_SIZE);

    //several messages are out of order or repeated
    for (uint16_t index = 0; index < check_count; index++)
    {
        uint64_t seq_number = incoming_numbers[index];
        bool result_valid = check_results[index];
        bool result = server_is_sequence_number_valid(seq_number, test_window, WINDOW_SIZE);
        zassert_equal(result_valid, result, "");

        if (result_valid)
        {
            //replay check OK - after MAC verification, window can be updated
            server_replay_window_update(seq_number, test_window, WINDOW_SIZE);
        }
    }
    zassert_mem_equal(test_window, compare_window_1, size, "");

    //proper reception of multiple messages, to make sure that in real scenario window can do its job
    for (uint64_t seq_number = 10; seq_number <= 50; seq_number++)
    {
        bool result = server_is_sequence_number_valid(seq_number, test_window, WINDOW_SIZE);
        zassert_equal(true, result, "");

        server_replay_window_update(seq_number, test_window, WINDOW_SIZE);
    }
    zassert_mem_equal(test_window, compare_window_2, size, "");
}


void run_replay_protection_tests(void)
{
    ztest_test_suite(oscore_replay_protection,
                    ztest_unit_test(server_replay_init_test),
                    ztest_unit_test(server_replay_beginning_test),
                    ztest_unit_test(server_replay_in_progress_test),
                    ztest_unit_test(server_replay_insert_test),
                    ztest_unit_test(server_replay_standard_scenario_test)
                    );

    ztest_run_test_suite(oscore_replay_protection);
}
