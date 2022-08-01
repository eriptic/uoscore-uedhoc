#include <stdbool.h>
#include <string.h>

#include "oscore/replay_protection.h"

/**
 * @brief Insert given sequence number in the specified position of replay window.

 * @param seq_number [in] sequence number to be inserted
 * @param replay_window [out] replay window array pointer
 * @param position [in] index to place new number (all older elements will be left-shifted)
 */
static void server_replay_window_insert(uint64_t seq_number,
					uint64_t *replay_window,
					uint8_t position)
{
	/*shift all old values one position to the left*/
	size_t shift_length = position * sizeof(replay_window[0]);
	memmove(replay_window, replay_window + 1, shift_length);

	/*insert the new sender sequence number at a given position*/
	replay_window[position] = seq_number;
}

enum err server_replay_window_init(uint64_t *replay_window,
				   uint8_t replay_window_len)
{
	if ((NULL == replay_window) || (0 == replay_window_len)) {
		return wrong_parameter;
	}

	memset(replay_window, 0, replay_window_len * sizeof(replay_window[0]));
	return ok;
}

bool server_is_sequence_number_valid(uint64_t seq_number,
				     uint64_t *replay_window,
				     uint8_t replay_window_len)
{
	/*if the sender sequence number is bigger than the
    right most element -> all good */
	if (seq_number > replay_window[replay_window_len - 1]) {
		return true;
	}

	/*if the sender sequence number is smaller than the
    left most element -> a replay is detected*/
	if (seq_number < replay_window[0]) {
		return false;
	}

	/*if the sender sequence number is in the replay window
    -> a replay is detected*/
	for (uint8_t i = 0; i < replay_window_len; i++) {
		if (seq_number == replay_window[i]) {
			return false;
		}
	}

	return true;
}

void server_replay_window_update(uint64_t seq_number, uint64_t *replay_window,
				 uint8_t replay_window_len)
{
	uint16_t index;
	for (index = 0; index < replay_window_len - 1; index++) {
		if ((replay_window[index] < seq_number) &&
		    (replay_window[index + 1] > seq_number)) {
			break;
		}
	}
	server_replay_window_insert(seq_number, replay_window, index);
}
