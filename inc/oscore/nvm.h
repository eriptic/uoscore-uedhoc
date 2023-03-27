/*
   Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef NVM_H
#define NVM_H

#include "common/byte_array.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief Public fields of the security context which can be used to find the right slot in the NVM.
 *        The usage of given fields is up to user's implementation.
 *        For more details, see nvm_write_ssn and nvm_read_ssn.
 */
struct nvm_key_t {
	struct byte_array sender_id;
	struct byte_array recipient_id;
	struct byte_array id_context;
};

#ifdef OSCORE_NVM_SUPPORT
/**
* @brief When the same OSCORE master secret and salt are reused through
*        several reboots of the device, e.g., no fresh shared secret is
*        derived through EDHOC (or some other method) the Sender Sequence 
*        Number MUST be stored periodically in NVM. 
* @param nvm_key part of the context that is permitted to be used for identifying the right store slot in NVM.
* @param	ssn SSN to be written in NVM.
* @retval ok or error code if storing the SSN was not possible.
*/
enum err nvm_write_ssn(const struct nvm_key_t *nvm_key, uint64_t ssn);

/**
* @brief When the same OSCORE master secret and salt are reused through
*        several reboots of the device, e.g., no fresh shared secret is
*        derived through EDHOC (or some other method) the Sender Sequence 
*        Number MUST be restored from NVM at each reboot. 
* @param nvm_key part of the context that is permitted to be used for identifying the right store slot in NVM.
* @param	ssn SSN to be read out from NVM.
* @retval ok or error code if the retrieving the SSN was not possible.
*/
enum err nvm_read_ssn(const struct nvm_key_t *nvm_key, uint64_t *ssn);

/**
 * @brief Periodically stores the SSN in NVM (if needed).
 * 
 * @param nvm_key part of the context that is permitted to be used for identifying the right store slot in NVM.
 * @param ssn SSN to be written in NVM.
 * @param echo_sync_in_progress Indicates if the device is still in the ECHO synchronization mode.
 * @return enum err 
 */
enum err ssn_store_in_nvm(const struct nvm_key_t *nvm_key, uint64_t ssn,
			  bool echo_sync_in_progress);
#endif

/**
 * @brief Initializes the SSN depending on context freshness.
 * @param nvm_key part of the context that is permitted to be used for identifying the right store slot in NVM.
 * @param ssn Pointer which will be updated with the value read from NVM.
 * @param is_context_fresh Indicates if the context is fresh, or the value needs to be retrieved from NVM.
 * @retval error code
*/
enum err ssn_init(const struct nvm_key_t *nvm_key, uint64_t *ssn,
		  bool is_context_fresh);

#endif
