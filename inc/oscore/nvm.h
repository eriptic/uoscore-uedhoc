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

#include "oscore.h"
#include "common/oscore_edhoc_error.h"

/**
 * @brief   When the same OSCORE master secret and salt are reused through
 * 			several reboots of the device, e.g., no fresh shared secret is
 * 			derived through EDHOC (or some other method) the Sender Sequence 
 * 			Number MUST be stored periodically in NVM. 
 * @param	sender_id the user may use the sender_id as a key in a table in 
 * 			NVM holding SSNs for different sender contexts. 
 * @param   id_context id of the context. To be used as an additional key 
 * @param	ssn the ssn to be written in NVM
 * @retval	ok or error code if storing the SSN was not possible.
 */
enum err nvm_write_ssn(const struct byte_array *sender_id,
			    const struct byte_array *id_context, uint64_t ssn);

/**
 * @brief   When the same OSCORE master secret and salt are reused through
 * 			several reboots of the device, e.g., no fresh shared secret is
 * 			derived through EDHOC (or some other method) the Sender Sequence 
 * 			Number MUST be restored from NVM at each reboot. 
 * @param	sender_id the user may use the sender_id as a key in a table in 
 * 			NVM holding SSNs for different sender contexts. 
 * @param   id_context id of the context. To be used as an additional key 
 * @param	ssn the ssn to be read out from NVM
 * @retval	ok or error code if the retrieving the SSN was not possible.
 */
enum err nvm_read_ssn(const struct byte_array *sender_id,
			   const struct byte_array *id_context, uint64_t *ssn);

/**
 * @brief   Stores the SSN in NVM if ssn_in_nvm is true.
 * @param   sender_id id of the sender. To be used for identifying the 
 *          right store location.
 * @param   id_context id of the context. To be used as an additional key 
 *          for identifying the right store location.
 * @param   ssn the value to be stored
 * @param   ssn_in_nvm indicates if it is necessary to store the SSN
 * @retval  error code
*/
enum err ssn_store_in_nvm(const struct byte_array *sender_id,
			  const struct byte_array *id_context, uint64_t ssn,
			  bool ssn_in_nvm);

/**
 * @brief   Initializes the SSN after reboot.
 * @param   sender_id id of the sender. To be used for identifying the 
 *          right store slot in NVM.
 * @param   id_context id of the context. To be used as an additional key 
 *          for identifying the right store location.
 * @param   ssn the value to initialized
 * @param   ssn_in_nvm indicates if the value needs to be retrievd from SSN
 * @retval  error code
*/
enum err ssn_init(const struct byte_array *sender_id,
		  const struct byte_array *id_context, uint64_t *ssn,
		  bool ssn_in_nvm);
#endif
