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
 * @brief			Retrieves the credential of the other party and 
 * 				its static DH key when static DH 
 * 				authentication is used or public signature key 
 *				when digital signatures are used. 
 *
 * @param static_dh_auth 	True if static DH authentication is used. 
 * @param cred_array 		An array containing credentials. 
 * @param[in] id_cred 		ID_CRED_x.
 * @param[out] cred 		CRED_x.
 * @param[out] pk 		Public key.
 * @param[out] g 		Static DH public key.
 * @retval			Ok or error.
 */
enum err retrieve_cred(bool static_dh_auth, struct cred_array *cred_array,
		       struct byte_array *id_cred, struct byte_array *cred,
		       struct byte_array *pk, struct byte_array *g);

#endif
