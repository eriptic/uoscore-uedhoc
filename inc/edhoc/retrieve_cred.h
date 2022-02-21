/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef RETRIEVE_CRED_H
#define RETRIEVE_CRED_H

#include <stdbool.h>
#include <stdint.h>

#include "edhoc.h"

#include "common/oscore_edhoc_error.h"

enum id_cred_x_label {
	/*ID_CRED_x contains a key ID used to identify a pre established RPK*/
	kid = 4,
	
	/* ID_CRED_x contains an unordered bag of X.509 certificates*/
	x5bag = 32,
	/* ID_CRED_x contains an certificate chain*/
	x5chain = 33,
	/*ID_CRED_x contains a hash used to identify a pre established cert*/
	x5t = 34,
	/*ID_CRED_x contains an uri used to identify a pre established cert*/
	x5u = 35,
	
	/* ID_CRED_x contains an unordered bag of C509 certificates*/
	c5b = 52,
	/* ID_CRED_x contains an certificate chain of C509 certificates*/
	c5c = 53,
	/*ID_CRED_x contains a hash used to identify a pre established C509 cert*/
	c5t = 54,
	/*ID_CRED_x contains an uri used to identify a pre established C509 cert*/
	c5u = 55,	
};

/**
 * @brief   retrives the credential of the other party and its static DH key 
 *          and when static DH authentication is used or public signature key 
 *          when digital signatures are used 
 * @param   static_dh_auth true if static DH authentication is used
 * @param   cred_array an array containing credentials 
 * @param   cred_num number of elements in cred_array
 * @param   id_cred ID_CRED_x
 * @param   id_cred_len length of id_cred
 * @param   cred CRED_x
 * @param   cred_len length of cred
 * @param   pk public key
 * @param   pk_len length of pk
 * @param   g static DH public key
 * @param   g_len length of g
 */
enum err retrieve_cred(bool static_dh_auth, struct other_party_cred *cred_array,
		       uint16_t cred_num, uint8_t *id_cred,
		       uint32_t id_cred_len, uint8_t *cred, uint32_t *cred_len,
		       uint8_t *pk, uint32_t *pk_len, uint8_t *g,
		       uint32_t *g_len);

#endif
