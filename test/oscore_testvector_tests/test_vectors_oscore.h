/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef TEST_VECTORS_OSCORE
#define TEST_VECTORS_OSCORE

#include <stdint.h>
/**
 * Test 1:
 * - Key derivation without master salt see RFC8613 Appendix C.1.1
 * - Generating OSCORE request with key form C.1.1  
 */

/*Test vector C1.1: Key derivation with Master Salt*/
extern uint8_t T1__MASTER_SECRET[16];
extern uint8_t T1__MASTER_SECRET_LEN;

extern uint8_t *T1__SENDER_ID;
extern uint8_t T1__SENDER_ID_LEN;

extern uint8_t T1__RECIPIENT_ID[1];
extern uint8_t T1__RECIPIENT_ID_LEN;

extern uint8_t T1__MASTER_SALT[8];
extern uint8_t T1__MASTER_SALT_LEN;

extern uint8_t *T1__ID_CONTEXT;
extern uint8_t T1__ID_CONTEXT_LEN;

/*Test vector C4: Generating a OSCORE Packet with key material form test vector C.1 */
extern uint8_t T1__COAP_REQ[];
extern uint16_t T1__COAP_REQ_LEN;

/*Expected result*/
extern uint8_t T1__SENDER_KEY[];
extern uint8_t T1__SENDER_KEY_LEN;

extern uint8_t T1__RECIPIENT_KEY[];
extern uint8_t T1__RECIPIENT_KEY_LEN;

extern uint8_t T1__COMMON_IV[];
extern uint8_t T1__COMMON_IV_LEN;

extern uint8_t T1__OSCORE_REQ[];
extern uint8_t T1__OSCORE_REQ_LEN;

/**
 * Test 2:
 * - Server Key derivation without master salt see RFC8613 Appendix C.1.2
 * - Generating OSCORE response with key form C.1.2 see RFC8613 Appendix C.7 
 */
extern uint8_t T2__MASTER_SECRET[16];
extern uint8_t T2__MASTER_SECRET_LEN;

extern uint8_t T2__SENDER_ID[];
extern uint8_t T2__SENDER_ID_LEN;

extern uint8_t T2__RECIPIENT_ID[];
extern uint8_t T2__RECIPIENT_ID_LEN;

extern uint8_t T2__MASTER_SALT[];
extern uint8_t T2__MASTER_SALT_LEN;

extern uint8_t *T2__ID_CONTEXT;
extern uint8_t T2__ID_CONTEXT_LEN;

/*The OSCORE message created in C4 (35 Byte). Constructed from a CoAP request of length 22. This request contains no payload. The request contains only Uri-host (locahost) and Uri-path option (tv1). In the OSCORE packet Uri-host option is transferred as plain normal option, The Uri-path is contained in the ciphertext. */
extern uint8_t T2__OSCORE_REQ[];
extern uint8_t T2__OSCORE_REQ_LEN;

/*Unprotected CoAP response (21 bytes)*/
/*Contains the payload "Hello World!"*/
extern uint8_t T2__COAP_RESPONSE[];
extern uint8_t T2__COAP_RESPONSE_LEN;

/*Expected result*/
/*the  reconstructed coap request see Appendix C4*/
extern uint8_t T2__COAP_REQ[];
extern uint8_t T2__COAP_REQ_LEN;

extern uint8_t T2__OSCORE_RESP[];
extern uint8_t T2__OSCORE_RESP_LEN;

/**
 * Test 3:
 * - Client Key derivation without master salt see RFC8613 Appendix C.2.1
 * - Generating OSCORE request with key form C.2.1 see RFC8613 Appendix C.5 
 */
/*Test vector C2.1: Key derivation without Master Salt*/
extern uint8_t T3__MASTER_SECRET[16];
extern uint8_t T3__MASTER_SECRET_LEN;

extern uint8_t T3__SENDER_ID[1];
extern uint8_t T3__SENDER_ID_LEN;

extern uint8_t T3__RECIPIENT_ID[1];
extern uint8_t T3__RECIPIENT_ID_LEN;

extern uint8_t *T3__MASTER_SALT;
extern uint8_t T3__MASTER_SALT_LEN;

extern uint8_t *T3__ID_CONTEXT;
extern uint8_t T3__ID_CONTEXT_LEN;

/*Test vector C5: Generating a OSCORE Packet with key material form test vector C.2.1 */
extern uint8_t T3__COAP_REQ[];
extern uint16_t T3__COAP_REQ_LEN;

/*expected result*/
extern uint8_t T3__OSCORE_REQ[];
extern uint8_t T3__OSCORE_REQ_LEN;

/**
 * Test 4:
 * - Server Key derivation without master salt see RFC8613 Appendix C.2.2
 */
/*Test vector C2.2: Key derivation without Master Salt*/
extern uint8_t T4__MASTER_SECRET[16];
extern uint8_t T4__MASTER_SECRET_LEN;

extern uint8_t T4__SENDER_ID[1];
extern uint8_t T4__SENDER_ID_LEN;

extern uint8_t T4__RECIPIENT_ID[1];
extern uint8_t T4__RECIPIENT_ID_LEN;

extern uint8_t *T4__MASTER_SALT;
extern uint8_t T4__MASTER_SALT_LEN;

extern uint8_t *T4__ID_CONTEXT;
extern uint8_t T4__ID_CONTEXT_LEN;

/*expected result*/
extern uint8_t T4__SENDER_KEY[];
extern uint8_t T4__SENDER_KEY_LEN;

extern uint8_t T4__RECIPIENT_KEY[];
extern uint8_t T4__RECIPIENT_KEY_LEN;

extern uint8_t T4__COMMON_IV[];
extern uint8_t T4__COMMON_IV_LEN;

/**
 * Test 5 :
 * - Client Key derivation with ID Context see Appendix 3.1
 * - OSCORE request generation see Appendix C6
 */
/*Test vector C3.1: Key derivation with ID Context*/
extern uint8_t T5__MASTER_SECRET[16];
extern uint8_t T5__MASTER_SECRET_LEN;

extern uint8_t *T5__SENDER_ID;
extern uint8_t T5__SENDER_ID_LEN;

extern uint8_t T5__RECIPIENT_ID[1];
extern uint8_t T5__RECIPIENT_ID_LEN;

extern uint8_t T5__MASTER_SALT[8];
extern uint8_t T5__MASTER_SALT_LEN;

extern uint8_t T5__ID_CONTEXT[8];
extern uint8_t T5__ID_CONTEXT_LEN;

/*Test vector C6: Generating a OSCORE Packet with key material form test vector C.3.1 */
extern uint8_t T5__COAP_REQ[];
extern uint16_t T5__COAP_REQ_LEN;

/*Expected result*/
extern uint8_t T5__OSCORE_REQ[];
extern uint8_t T5__OSCORE_REQ_LEN;

/**
 * Test 6:
 * - Server Key derivation with ID context see RFC8613 Appendix C.3.2
 */
extern uint8_t T6__MASTER_SECRET[16];
extern uint8_t T6__MASTER_SECRET_LEN;

extern uint8_t T6__SENDER_ID[1];
extern uint8_t T6__SENDER_ID_LEN;

extern uint8_t *T6__RECIPIENT_ID;
extern uint8_t T6__RECIPIENT_ID_LEN;

extern uint8_t T6__MASTER_SALT[8];
extern uint8_t T6__MASTER_SALT_LEN;

extern uint8_t T6__ID_CONTEXT[8];
extern uint8_t T6__ID_CONTEXT_LEN;

/*expected result*/
extern uint8_t T6__SENDER_KEY[];
extern uint8_t T6__SENDER_KEY_LEN;

extern uint8_t T6__RECIPIENT_KEY[];
extern uint8_t T6__RECIPIENT_KEY_LEN;

extern uint8_t T6__COMMON_IV[];
extern uint8_t T6__COMMON_IV_LEN;

/**
 * Test 7:
 * - Server with partial IV see Appendix C8
 */
extern uint8_t T7__MASTER_SECRET[16];
extern uint8_t T7__MASTER_SECRET_LEN;

extern uint8_t T7__SENDER_ID[];
extern uint8_t T7__SENDER_ID_LEN;

extern uint8_t *T7__RECIPIENT_ID;
extern uint8_t T7__RECIPIENT_ID_LEN;

extern uint8_t T7__MASTER_SALT[8];
extern uint8_t T7__MASTER_SALT_LEN;

extern uint8_t *T7__ID_CONTEXT;
extern uint8_t T7__ID_CONTEXT_LEN;

/*Test vector C4: Generating a OSCORE Packet with key material form test vector C.1 */
/*the OSCORE message created in C4*/
extern uint8_t T7__OSCORE_REQ[];
extern uint8_t T7__OSCORE_REQ_LEN;

/*unprotected CoAP response*/
extern uint8_t T7__COAP_RESPONSE[];
extern uint8_t T7__COAP_RESPONSE_LEN;

/*expected result*/
extern uint8_t T7__OSCORE_RES[];
extern uint8_t T7__OSCORE_RES_LEN;

/**
 * Test 8:
 * - Simple ACK packet should not be encrypted and result should be the same as input buffer (see RFC8613 Section 4.2)
 */
extern uint8_t T8__MASTER_SECRET[16];
extern uint8_t T8__MASTER_SECRET_LEN;

extern uint8_t T8__SENDER_ID[];
extern uint8_t T8__SENDER_ID_LEN;

extern uint8_t *T8__RECIPIENT_ID;
extern uint8_t T8__RECIPIENT_ID_LEN;

extern uint8_t T8__MASTER_SALT[8];
extern uint8_t T8__MASTER_SALT_LEN;

extern uint8_t *T8__ID_CONTEXT;
extern uint8_t T8__ID_CONTEXT_LEN;

/*Simple ACK message (code 0=EMPTY, type 2=ACK, no payload).*/
extern uint8_t T8__COAP_ACK[];
extern uint8_t T8__COAP_ACK_LEN;

#endif