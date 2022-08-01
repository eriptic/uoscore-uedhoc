#ifndef REPLAY_PROTECTION_H
#define REPLAY_PROTECTION_H

#include <stdint.h>
#include <stdbool.h>
#include "common/oscore_edhoc_error.h"

/**
 * @brief Initialize given replay window with default values.
 *
 * @param replay_window [out] a pointer to replay window
 * @param replay_window_len [in] elements count of replay window
 * @return err
 */
enum err server_replay_window_init(uint64_t *replay_window,
				   uint8_t replay_window_len);

/**
 * @brief Check whether given sequence number is valid in terms of server replay protection.
 *
 * @param seq_number [in] sequence number of the message received by the server
 * @param replay_window [in] a pointer to replay window
 * @param replay_window_len [in] elements count of replay window
 * @return true if ok, false otherwise
 */
bool server_is_sequence_number_valid(uint64_t seq_number,
				     uint64_t *replay_window,
				     uint8_t replay_window_len);

/**
 * @brief Update given replay window with last received sequence number.
 *
 * @param seq_number [in] sequence number of the message received by the server
 * @param replay_window [out] a pointer to replay window
 * @param replay_window_len [in] elements count of replay window
 */
void server_replay_window_update(uint64_t seq_number, uint64_t *replay_window,
				 uint8_t replay_window_len);

#endif
