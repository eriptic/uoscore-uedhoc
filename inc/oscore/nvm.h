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
 * @brief   Stores the SSN in NVM if ssn_in_nvm is true.
 * @param   sender_id id of the sender. To be used for identifying the 
 *          right store location.
 * @param   ssn the value to be stored
 * @param   ssn_in_nvm indicates if it is necessary to store the SSN
 * @retval  error code
*/
enum err ssn_store_in_nvm(const struct byte_array *sender_id, uint64_t ssn,
			  bool ssn_in_nvm);
/**
 * @brief   Initializes the SSN after reboot.
 * @param   sender_id id of the sender. To be used for identifying the 
 *          right store slot in NVM.
 * @param   ssn the value to initialized
 * @param   ssn_in_nvm indicates if the value needs to be retrievd from SSN
 * @retval  error code
*/
enum err ssn_init(const struct byte_array *sender_id, uint64_t *ssn,
		  bool ssn_in_nvm);
#endif