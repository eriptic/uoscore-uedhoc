/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef CREDENTIALS
#define CREDENTIALS

#include <stdint.h>

#include "credentials_select.h"

#if defined INITIATOR_TEST_1 || defined INITIATOR_TEST_2 ||                    \
	defined INITIATOR_TEST_3 || defined INITIATOR_TEST_4 ||                \
	defined INITIATOR_TEST_5
extern enum method_type METHOD_TYPE;
extern uint8_t CORR;

extern uint8_t SUITES_I[];
extern uint32_t SUITES_I_LEN;

extern uint8_t G_X[];
extern uint32_t G_X_LEN;

extern uint8_t X[];
extern uint32_t X_LEN;

extern uint8_t C_I[];
extern uint32_t C_I_LEN;

extern uint8_t AD_1[];
extern uint32_t AD_1_LEN;

extern uint8_t AD_3[];
extern uint32_t AD_3_LEN;

extern uint8_t I[];
extern uint32_t I_LEN;

extern uint8_t G_I[];
extern uint32_t G_I_LEN;

extern uint8_t ID_CRED_I[];
extern uint32_t ID_CRED_I_LEN;

extern uint8_t CRED_I[];
extern uint32_t CRED_I_LEN;

extern uint8_t SK_I[];
extern uint32_t SK_I_LEN;

extern uint8_t PK_I[];
extern uint32_t PK_I_LEN;

/*other party credentials*/
extern uint8_t ID_CRED_R[];
extern uint32_t ID_CRED_R_LEN;

extern uint8_t CRED_R[];
extern uint32_t CRED_R_LEN;

extern uint8_t PK_R[];
extern uint32_t PK_R_LEN;

extern uint8_t G_R[];
extern uint32_t G_R_LEN;

extern uint8_t CA[];
extern uint32_t CA_LEN;

extern uint8_t CA_PK[];
extern uint32_t CA_PK_LEN;
#endif

#if defined RESPONDER_TEST_1 || defined RESPONDER_TEST_2 ||                    \
	defined RESPONDER_TEST_3 || defined RESPONDER_TEST_4 ||                \
	defined RESPONDER_TEST_5
extern uint8_t SUITES_R[];
extern uint32_t SUITES_R_LEN;

extern uint8_t G_Y[];
extern uint32_t G_Y_LEN;

extern uint8_t Y[];
extern uint32_t Y_LEN;

extern uint8_t C_R[];
extern uint32_t C_R_LEN;

extern uint8_t AD_2[];
extern uint32_t AD_2_LEN;

extern uint8_t ID_CRED_R[];
extern uint32_t ID_CRED_R_LEN;

extern uint8_t CRED_R[];
extern uint32_t CRED_R_LEN;

extern uint8_t SK_R[];
extern uint32_t SK_R_LEN;

extern uint8_t PK_R[];
extern uint32_t PK_R_LEN;

extern uint8_t R[];
extern uint32_t R_LEN;

extern uint8_t G_R[];
extern uint32_t G_R_LEN;

/*other party credentials*/
extern uint8_t ID_CRED_I[];
extern uint32_t ID_CRED_I_LEN;

extern uint8_t CRED_I[];
extern uint32_t CRED_I_LEN;

extern uint8_t PK_I[];
extern uint32_t PK_I_LEN;

extern uint8_t G_I[];
extern uint32_t G_I_LEN;

extern uint8_t CA[];
extern uint32_t CA_LEN;

extern uint8_t CA_PK[];
extern uint32_t CA_PK_LEN;
#endif

#if (defined INITIATOR_TEST_1) || (defined RESPONDER_TEST_1) ||                \
	(defined INITIATOR_TEST_2) || (defined RESPONDER_TEST_2) ||            \
	(defined INITIATOR_TEST_3) || (defined RESPONDER_TEST_3) ||            \
	(defined INITIATOR_TEST_4) || (defined RESPONDER_TEST_4) ||            \
	(defined INITIATOR_TEST_5) || (defined RESPONDER_TEST_5)

extern uint8_t MSG_1[];
extern uint32_t MSG_1_LEN;

extern uint8_t MSG_2[];
extern uint32_t MSG_2_LEN;

extern uint8_t MSG_3[];
extern uint32_t MSG_3_LEN;
#endif

#endif /* CREDENTIALS */
