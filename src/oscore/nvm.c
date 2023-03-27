/*
   Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#include <inttypes.h>

#include "edhoc.h"
#include "oscore.h"

#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

#ifdef OSCORE_NVM_SUPPORT
enum err WEAK nvm_write_ssn(const struct nvm_key_t *nvm_key, uint64_t ssn)
{
	PRINT_MSG(
		"The nvm_write_ssn() function MUST be overwritten by user!!!\n");
	return not_implemented;
}

enum err WEAK nvm_read_ssn(const struct nvm_key_t *nvm_key, uint64_t *ssn)
{
	PRINT_MSG(
		"The nvm_read_ssn() function MUST be overwritten by user!!!\n");
	if (NULL != ssn) {
		*ssn = 0;
	}
	return not_implemented;
}

enum err ssn_store_in_nvm(const struct nvm_key_t *nvm_key, uint64_t ssn,
			  bool echo_sync_in_progress)
{
	bool cyclic_write = (0 == ssn % K_SSN_NVM_STORE_INTERVAL);

	/* While the device is still in the ECHO synchronization mode (after device reboot or other context reinitialization)
	   SSN has to be written immediately, in case of uncontrolled reboot before first cyclic write happens. */
	if (cyclic_write || echo_sync_in_progress) {
		TRY(nvm_write_ssn(nvm_key, ssn));
	}
	return ok;
}
#endif

enum err ssn_init(const struct nvm_key_t *nvm_key, uint64_t *ssn,
		  bool is_context_fresh)
{
	if ((NULL == nvm_key) || (NULL == ssn)) {
		return wrong_parameter;
	}

	if (is_context_fresh) {
		*ssn = 0;
		PRINTF("Security context is fresh, SSN initialized to %" PRIu64
		       "\n",
		       *ssn);
	} else {
		#ifdef OSCORE_NVM_SUPPORT
			TRY(nvm_read_ssn(nvm_key, ssn));
			*ssn += K_SSN_NVM_STORE_INTERVAL + F_NVM_MAX_WRITE_FAILURE;
			PRINTF("SSN initialized from NMV. SSN = %" PRIu64 "\n", *ssn);
		#else
			PRINT_MSG("OSCORE_NVM_SUPPORT flag must be defined for handling non-fresh (stored) contexts.");
			return not_implemented;
		#endif
	}
	return ok;
}