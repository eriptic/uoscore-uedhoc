/*
   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef CORRELATION_H
#define CORRELATION_H

#include <stdint.h>

#include "edhoc.h"

#define CBOR_TRUE 0xf5

enum role {
	INITIATOR_CLIENT,
	INITIATOR_SERVER,
	RESPONDER_CLIENT,
	RESPONDER_SERVER,
};

enum correlator_type {
	TRANSPORT,
	C_x,
};

struct state_i {
	/*own correlator can be provided from transport or be C_I.
	The own correlator is used to corelate incoming messges 
	at the initiator side*/
	uint8_t own_corr[CORR_DEFAULT_SIZE];
	uint32_t own_corr_len;

	/*other party correlator can be provided from transport or be C_R*/
	uint8_t other_party_corr[CORR_DEFAULT_SIZE];
	uint32_t other_party_corr_len;
	bool cr_set;
};

struct state_r {
	/*own correlator can be provided from transport or C_R*/
	uint8_t own_corr[CORR_DEFAULT_SIZE];
	uint32_t own_corr_len;

	/*other party correlator can be provided from transport or C_I*/
	uint8_t other_party_corr[CORR_DEFAULT_SIZE];
	uint32_t other_party_corr_len;
};



#endif