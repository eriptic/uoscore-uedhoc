/*
   Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include "edhoc.h"
#include "oscore.h"

#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

/**
 * @brief   When the same OSCORE master secret and salt are reused through
 * 			several reboots of the device, e.g., no fresh shared secret is
 * 			derived through EDHOC (or some other method) the Sender Sequence 
 * 			Number MUST be stored periodically in NVM. 
 * @param	sender_id the user may use the sender_id as a key in a table in 
 * 			NVM holding SSNs for different sender contexts. 
 * @param	ssn the ssn to be written in NVM
 * @retval	ok or error code if the retrieving the SSN was not possible.
 */
enum err WEAK nvm_write_ssn(const struct byte_array *sender_id, uint64_t ssn)
{
#warning "The nvm_write_ssn() function MUST be overwritten by user!!!\n"

	return ok;
}

/**
 * @brief   When the same OSCORE master secret and salt are reused through
 * 			several reboots of the device, e.g., no fresh shared secret is
 * 			derived through EDHOC (or some other method) the Sender Sequence 
 * 			Number MUST be restored from NVM at each reboot in order to prevent 
 *          reusing the same nonce for encrypting different plain texts. 
 * @param	c the complete context. The user must use the context for 
 * 			retrieving the corrsponding sender sequence number from NVM. 
 * 			The retrievd value must be written in c->sc.ssn.
 * @retval	ok or error code if the retrieving the SSN was not possible.
 */
enum err WEAK nvm_read_ssn(const struct byte_array *sender_id, uint64_t *ssn)
{
#warning "The nvm_read_ssn() function MUST be overwritten by user!!!\n"
	*ssn = 0;
	return ok;
}

enum err ssn_store_in_nvm(const struct byte_array *sender_id, uint64_t ssn,
			  bool ssn_in_nvm)
{
	if (ssn_in_nvm && (0 == ssn % K_SSN_NVM_STORE_INTERVAL)) {
		TRY(nvm_write_ssn(sender_id, ssn));
	}
	return ok;
}

enum err ssn_init(const struct byte_array *sender_id, uint64_t *ssn,
		  bool ssn_in_nvm)
{
	if (!ssn_in_nvm) {
		*ssn = 0;
		PRINTF("SSN initialized not from NMV. SSN = %llu\n", *ssn);
	} else {
		TRY(nvm_read_ssn(sender_id, ssn));
		*ssn += K_SSN_NVM_STORE_INTERVAL + F_NVM_MAX_WRITE_FAILURE;
		PRINTF("SSN initialized from NMV. SSN = %llu\n", *ssn);
	}
	return ok;
}