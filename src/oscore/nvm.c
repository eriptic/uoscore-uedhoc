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

enum err WEAK nvm_write_ssn(const struct byte_array *sender_id,
			    const struct byte_array *id_context, uint64_t ssn)
{
	PRINT_MSG("The nvm_write_ssn() function MUST be overwritten by user!!!\n");
	return not_implemented;
}

enum err WEAK nvm_read_ssn(const struct byte_array *sender_id,
			   const struct byte_array *id_context, uint64_t *ssn)
{
	PRINT_MSG("The nvm_read_ssn() function MUST be overwritten by user!!!\n");
	*ssn = 0;
	return not_implemented;
}

enum err ssn_store_in_nvm(const struct byte_array *sender_id,
			  const struct byte_array *id_context, uint64_t ssn,
			  bool ssn_in_nvm)
{
	if (ssn_in_nvm && (0 == ssn % K_SSN_NVM_STORE_INTERVAL)) {
		TRY(nvm_write_ssn(sender_id, id_context, ssn));
	}
	return ok;
}

enum err ssn_init(const struct byte_array *sender_id,
		  const struct byte_array *id_context, uint64_t *ssn,
		  bool ssn_in_nvm)
{
	if (!ssn_in_nvm) {
		*ssn = 0;
		PRINTF("SSN initialized not from NMV. SSN = %lu\n", *ssn);
	} else {
		TRY(nvm_read_ssn(sender_id, id_context, ssn));
		*ssn += K_SSN_NVM_STORE_INTERVAL + F_NVM_MAX_WRITE_FAILURE;
		PRINTF("SSN initialized from NMV. SSN = %lu\n", *ssn);
	}
	return ok;
}