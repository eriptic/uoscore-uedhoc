#include <stdbool.h>
#include <string.h>

#include "oscore/replay_protection.h"
#include "oscore/security_context.h"
#include "common/memcpy_s.h"
#include "common/byte_array.h"

#define WINDOW_SIZE OSCORE_SERVER_REPLAY_WINDOW_SIZE

/**
 * @brief Insert given sequence number in the specified position of replay window.

 * @param seq_number [in] sequence number to be inserted
 * @param replay_window [out] replay window array pointer
 * @param position [in] index to place new number (all older elements will be left-shifted)
 */
static void server_replay_window_insert(uint64_t seq_number,
					struct server_replay_window_t *replay_window,
					size_t position)
{
	uint64_t *window = replay_window->window;

	/*shift all old values one position to the left*/
	size_t shift_length = position * sizeof(window[0]);
	memmove(window, window + 1, shift_length);

	/*insert the new sender sequence number at a given position*/
	window[position] = seq_number;
}

enum err server_replay_window_init(struct server_replay_window_t *replay_window)
{
	if (NULL == replay_window) {
		return wrong_parameter;
	}

	memset(replay_window->window, 0,
	       WINDOW_SIZE * sizeof(replay_window->window[0]));
	replay_window->seq_num_zero_received = false;
	return ok;
}

enum err server_replay_window_reinit(uint64_t current_sequence_number,
				     struct server_replay_window_t *replay_window)
{
	if (NULL == replay_window) {
		return wrong_parameter;
	}

	/*fill the window in a way that only new sequence numbers are accepted*/
	for (uint8_t j = 0; j < WINDOW_SIZE; j++) {
		replay_window->window[(WINDOW_SIZE - 1) - j] =
			current_sequence_number;
		if (current_sequence_number > 0) {
			current_sequence_number--;
		}
	}

	/* don't accept seqNum=0 anymore */
	replay_window->seq_num_zero_received = true;

	return ok;
}

bool server_is_sequence_number_valid(uint64_t seq_number,
				     struct server_replay_window_t *replay_window)
{
	if (NULL == replay_window) {
		return false;
	}

	/* replay window uses zeros for unused entries, so in case of sequence number is 0, a little logic is needed */
	if (0 == seq_number) {
		if ((!replay_window->seq_num_zero_received) &&
		    (0 == replay_window->window[0])) {
			return true;
		}
		return false;
	}

	if (seq_number > replay_window->window[WINDOW_SIZE - 1]) {
		return true;
	}

	if (seq_number < replay_window->window[0]) {
		return false;
	}

	for (uint8_t i = 0; i < WINDOW_SIZE; i++) {
		if (seq_number == replay_window->window[i]) {
			return false;
		}
	}

	return true;
}

bool server_replay_window_update(uint64_t seq_number,
				 struct server_replay_window_t *replay_window)
{
	/* Although sequence number should be checked before by the calling function, do it again to prevent possible security issues in case it was not. */
	bool is_valid =
		server_is_sequence_number_valid(seq_number, replay_window);
	if (!is_valid) {
		return false;
	}

	if (seq_number == 0) {
		replay_window->seq_num_zero_received = true;
		return true;
	}

	uint16_t index;
	for (index = 0; index < WINDOW_SIZE - 1; index++) {
		/* when the loop doesn't find proper index to place the number, it will stop at index = WINDOW_SIZE-1 */
		if ((replay_window->window[index] < seq_number) &&
		    (replay_window->window[index + 1] > seq_number)) {
			break;
		}
	}
	server_replay_window_insert(seq_number, replay_window, index);
	return true;
}

enum err replay_protection_check_notification(uint64_t notification_num,
					      bool notification_num_initialized,
					      struct byte_array *piv)
{
	uint64_t ssn;
	TRY(piv2ssn(piv, &ssn));


	if (notification_num_initialized) {
		if (notification_num >= ssn) {
			PRINT_MSG("Replayed notification detected!\n");
			return oscore_replay_notification_protection_error;
		}
	}
	return ok;
}

enum err notification_number_update(uint64_t *notification_num,
				    bool *notification_num_initialized,
				    struct byte_array *piv)
{
	TRY(piv2ssn(piv, notification_num));
	*notification_num_initialized = true;
	return ok;
}