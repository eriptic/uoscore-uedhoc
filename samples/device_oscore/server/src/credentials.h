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

extern uint8_t MASTER_SECRET[];
extern uint8_t SENDER_ID[];
extern uint8_t RECIPIENT_ID[];
extern uint8_t MASTER_SALT[];
extern uint8_t ID_CONTEXT[];

extern uint8_t MASTER_SECRET_LEN;
extern uint8_t SENDER_ID_LEN;
extern uint8_t RECIPIENT_ID_LEN;
extern uint8_t MASTER_SALT_LEN;
extern uint8_t ID_CONTEXT_LEN;

#endif
