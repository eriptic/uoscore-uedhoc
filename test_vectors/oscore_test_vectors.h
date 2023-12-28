/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef OSCORE_TEST_VECTORS_H
#define OSCORE_TEST_VECTORS_H

#include "oscore.h"

extern const uint8_t T1__MASTER_SECRET[16];
extern uint8_t T1__MASTER_SECRET_LEN;
extern const uint8_t *T1__SENDER_ID;
extern uint8_t T1__SENDER_ID_LEN;
extern const uint8_t T1__RECIPIENT_ID[1];
extern uint8_t T1__RECIPIENT_ID_LEN;
extern const uint8_t T1__MASTER_SALT[8];
extern uint8_t T1__MASTER_SALT_LEN;
extern const uint8_t *T1__ID_CONTEXT;
extern uint8_t T1__ID_CONTEXT_LEN;
extern const uint8_t T1__COAP_REQ[];
extern uint16_t T1__COAP_REQ_LEN;
extern const uint8_t T1__SENDER_KEY[];
extern uint8_t T1__SENDER_KEY_LEN;
extern const uint8_t T1__RECIPIENT_KEY[];
extern uint8_t T1__RECIPIENT_KEY_LEN;
extern const uint8_t T1__COMMON_IV[];
extern uint8_t T1__COMMON_IV_LEN;
extern const uint8_t T1__OSCORE_REQ[];
extern uint8_t T1__OSCORE_REQ_LEN;
extern const uint8_t T1__OSCORE_RESP[];
extern uint8_t T1__OSCORE_RESP_LEN;
extern const uint8_t T1__COAP_RESPONSE[];
extern uint8_t T1__COAP_RESPONSE_LEN;
extern const uint8_t T2__MASTER_SECRET[16];
extern uint8_t T2__MASTER_SECRET_LEN;
extern uint8_t T2__SENDER_ID[];
extern uint8_t T2__SENDER_ID_LEN;
extern uint8_t *T2__RECIPIENT_ID;
extern uint8_t T2__RECIPIENT_ID_LEN;
extern const uint8_t T2__MASTER_SALT[8];
extern uint8_t T2__MASTER_SALT_LEN;
extern uint8_t *T2__ID_CONTEXT;
extern uint8_t T2__ID_CONTEXT_LEN;
extern const uint8_t T2__OSCORE_REQ[];
extern uint8_t T2__OSCORE_REQ_LEN;
extern const uint8_t T2__COAP_RESPONSE[];
extern uint8_t T2__COAP_RESPONSE_LEN;
extern const uint8_t T2__COAP_REQ[];
extern uint8_t T2__COAP_REQ_LEN;
extern const uint8_t T2__OSCORE_RESP[];
extern uint8_t T2__OSCORE_RESP_LEN;
extern const uint8_t T3__MASTER_SECRET[16];
extern uint8_t T3__MASTER_SECRET_LEN;
extern const uint8_t T3__SENDER_ID[1];
extern uint8_t T3__SENDER_ID_LEN;
extern const uint8_t T3__RECIPIENT_ID[1];
extern uint8_t T3__RECIPIENT_ID_LEN;
extern const uint8_t *T3__MASTER_SALT;
extern uint8_t T3__MASTER_SALT_LEN;
extern const uint8_t *T3__ID_CONTEXT;
extern uint8_t T3__ID_CONTEXT_LEN;
extern const uint8_t T3__COAP_REQ[];
extern uint16_t T3__COAP_REQ_LEN;
extern const uint8_t T3__OSCORE_REQ[];
extern uint8_t T3__OSCORE_REQ_LEN;
extern const uint8_t T4__MASTER_SECRET[16];
extern uint8_t T4__MASTER_SECRET_LEN;
extern const uint8_t T4__SENDER_ID[1];
extern uint8_t T4__SENDER_ID_LEN;
extern const uint8_t T4__RECIPIENT_ID[1];
extern uint8_t T4__RECIPIENT_ID_LEN;
extern const uint8_t *T4__MASTER_SALT;
extern uint8_t T4__MASTER_SALT_LEN;
extern const uint8_t *T4__ID_CONTEXT;
extern uint8_t T4__ID_CONTEXT_LEN;
extern const uint8_t T4__SENDER_KEY[];
extern const uint8_t T4__RECIPIENT_KEY[];
extern uint8_t T4__RECIPIENT_KEY_LEN;
extern const uint8_t T4__COMMON_IV[];
extern uint8_t T4__COMMON_IV_LEN;
extern const uint8_t T5__MASTER_SECRET[16];
extern uint8_t T5__MASTER_SECRET_LEN;
extern const uint8_t *T5__SENDER_ID;
extern uint8_t T5__SENDER_ID_LEN;
extern const uint8_t T5__RECIPIENT_ID[1];
extern uint8_t T5__RECIPIENT_ID_LEN;
extern const uint8_t T5__MASTER_SALT[8];
extern uint8_t T5__MASTER_SALT_LEN;
extern const uint8_t T5__ID_CONTEXT[8];
extern uint8_t T5__ID_CONTEXT_LEN;
extern const uint8_t T5__COAP_REQ[];
extern uint16_t T5__COAP_REQ_LEN;
extern const uint8_t T5__OSCORE_REQ[];
extern uint8_t T5__OSCORE_REQ_LEN;
extern const uint8_t T6__MASTER_SECRET[16];
extern uint8_t T6__MASTER_SECRET_LEN;
extern const uint8_t T6__SENDER_ID[1];
extern uint8_t T6__SENDER_ID_LEN;
extern const uint8_t *T6__RECIPIENT_ID;
extern uint8_t T6__RECIPIENT_ID_LEN;
extern const uint8_t T6__MASTER_SALT[8];
extern uint8_t T6__MASTER_SALT_LEN;
extern const uint8_t T6__ID_CONTEXT[8];
extern uint8_t T6__ID_CONTEXT_LEN;
extern const uint8_t T6__SENDER_KEY[];
extern uint8_t T6__SENDER_KEY_LEN;
extern const uint8_t T6__RECIPIENT_KEY[];
extern uint8_t T6__RECIPIENT_KEY_LEN;
extern const uint8_t T6__COMMON_IV[];
extern uint8_t T6__COMMON_IV_LEN;
extern const uint8_t T7__MASTER_SECRET[16];
extern uint8_t T7__MASTER_SECRET_LEN;
extern const uint8_t T7__SENDER_ID[];
extern uint8_t T7__SENDER_ID_LEN;
extern const uint8_t *T7__RECIPIENT_ID;
extern uint8_t T7__RECIPIENT_ID_LEN;
extern const uint8_t T7__MASTER_SALT[8];
extern uint8_t T7__MASTER_SALT_LEN;
extern const uint8_t *T7__ID_CONTEXT;
extern uint8_t T7__ID_CONTEXT_LEN;
extern const uint8_t T7__OSCORE_REQ[];
extern uint8_t T7__OSCORE_REQ_LEN;
extern const uint8_t T7__COAP_RESPONSE[];
extern uint8_t T7__COAP_RESPONSE_LEN;
extern const uint8_t T7__OSCORE_RES[];
extern uint8_t T7__OSCORE_RES_LEN;
extern const uint8_t T8__MASTER_SECRET[16];
extern uint8_t T8__MASTER_SECRET_LEN;
extern const uint8_t T8__SENDER_ID[];
extern uint8_t T8__SENDER_ID_LEN;
extern const uint8_t T8__MASTER_SALT[8];
extern uint8_t T8__MASTER_SALT_LEN;
extern const uint8_t T8__COAP_ACK[];
extern uint8_t T8__COAP_ACK_LEN;

#endif