#ifndef REPLAY_PROTECTION_H
#define REPLAY_PROTECTION_H

#include <stdint.h>
#include <stdbool.h>

#include "common/oscore_edhoc_error.h"
#include "common/byte_array.h"

/* Replay window size - it can be defined by the user here or outside of this file. */
/* NOTE: window size of 32 is the MINUMUM that is RFC-compliant. */
#ifndef OSCORE_SERVER_REPLAY_WINDOW_SIZE
#define OSCORE_SERVER_REPLAY_WINDOW_SIZE 32
#endif

/* Replay window structure, used internally. */
struct server_replay_window_t {
	uint64_t window[OSCORE_SERVER_REPLAY_WINDOW_SIZE];
	bool seq_num_zero_received; /* helper flag used for validation of sequence number 0 */
};

/**
 * @brief Initialize given replay window with default values.
 *
 * @param replay_window [out] a pointer to replay window structure
 * @return err
 */
enum err server_replay_window_init(struct server_replay_window_t *replay_window);

/**
 * @brief Re-initialize given replay window based on current sequence number.
 *
 * This could be used by the user to restore the session.
 * After restoring, replay protection will reject any packet with sequence number
 * that is not greater than the one provided in the argument.
 *
 * @param current_sequence_number [in] last sequence number that was received before the session was stored
 * @param replay_window [out] a pointer to replay window structure
 * @return err
 */
enum err server_replay_window_reinit(uint64_t current_sequence_number,
				     struct server_replay_window_t *replay_window);

/**
 * @brief Check whether given sequence number is valid in terms of server replay protection.
 *
 * @param seq_number [in] sequence number of the message received by the server
 * @param replay_window [in] a pointer to replay window structure
 * @return true if ok, false otherwise
 */
bool server_is_sequence_number_valid(uint64_t seq_number,
				     struct server_replay_window_t *replay_window);

/**
 * @brief Update given replay window with last received sequence number.
 *
 * @param seq_number [in] sequence number of the message received by the server
 * @param replay_window [out] a pointer to replay window structure
 * @return true if ok, false if sequence number is not valid (this indicates that calling function hasn't check the sequence number before)
 */
bool server_replay_window_update(uint64_t seq_number,
				 struct server_replay_window_t *replay_window);

/**
 * @brief	Checks if an notification is replayed 
 * @param	notification_num the notification number
 * @param	notification_num_initialized flag used to indicated if the 
 * 			notification number was initialized
 * @param	piv the PIV
 * @retval	error code or ok
*/
enum err replay_protection_check_notification(uint64_t notification_num,
					      bool notification_num_initialized,
					      struct byte_array *piv);

/**
 * @brief	Updates the notification number with value of the PIV
 * @param	notification_num pointer to the notification number
 * @param	notification_num_initialized flag used to indicated if the 
 * 			notification number was initialized
 * @param	piv the PIV
 * @retval	error code or ok
*/
enum err notification_number_update(uint64_t *notification_num,
				    bool *notification_num_initialized,
				    struct byte_array *piv);
#endif
