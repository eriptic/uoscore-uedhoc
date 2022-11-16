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

enum err WEAK nvm_write_ssn(struct context *c)
{
#warning "The nvm_write_ssn() function MUST be overwritten by user!!!\n"

	return ok;
}

enum err ssn_store_in_nvm(struct context *c)
{
	if (0 == c->sc.sender_seq_num % K_SSN_NVM_STORE_INTERVAL) {
		TRY(nvm_write_ssn(c));
	}
	return ok;
}

/**
 * @brief   When the same OSCORE master secret is reused through several 
 *          reboots of the device, i.e., no fresh shared secret is derived 
 *          through EDHOC (or some other method) the Sender Sequence Number 
 *          MUST be restored from NVM at each reboot in order to prevent 
 *          reusing the same nonce vor encrypting different plain texts. 
 * 
 * 
*/
enum err WEAK nvm_read_ssn(struct context *c)
{
#warning "The nvm_read_ssn() function MUST be overwritten by user!!!\n"

	return ok;
}

enum err ssn_init(bool fresh_master_secret_salt, struct context *c)
{
	if (fresh_master_secret_salt) {
		c->sc.sender_seq_num = 0;
	} else {
		TRY(nvm_read_ssn(c));
		c->sc.sender_seq_num +=
			K_SSN_NVM_STORE_INTERVAL + F_NVM_MAX_WRITE_FAILURE;
	}
	PRINTF("SSN initialized. SSN = %llu\n", c->sc.sender_seq_num);
	return ok;
}