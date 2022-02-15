/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef CREDENTIALS_H
#define CREDENTIALS_H

#include <oscore.h>

#ifdef OSCORE_PSK
/**
 * Each endpoint derives the parameters in the security context from a
 * small set of input parameters.  This can be done with  EDHOC or out of band.
*/
/*mandatory credentials*/
uint8_t MASTER_SECRET[16] = { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08,
			      0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f, 0x10 };
uint8_t MASTER_SECRET_LEN = sizeof(MASTER_SECRET);

uint8_t SENDER_ID[1] = { 0x01 };
uint8_t SENDER_ID_LEN = sizeof(SENDER_ID);

uint8_t *RECIPIENT_ID = NULL;
uint8_t RECIPIENT_ID_LEN = 0;

/*optional credentials*/
uint8_t MASTER_SALT[8] = { 0x9e, 0x7c, 0xa9, 0x22, 0x23, 0x78, 0x63, 0x40 };
uint8_t MASTER_SALT_LEN = sizeof(MASTER_SALT);

uint8_t *ID_CONTEXT = NULL;
uint8_t ID_CONTEXT_LEN = 0;
#endif

#endif
