/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <edhoc.h>
#include <stdbool.h>
#include <string.h>
#include "edhoc_tests.h"
bool rx_initiator_switch = false;

static uint8_t msg_cnt;

void rx_init(void)
{
	msg_cnt = 1;
}

enum err rx(void *sock, uint8_t *data, uint32_t *data_len)
{
	if (rx_initiator_switch) {
		PRINTF("TXRX wrapper test vectors\n");
		/*The initiator must get msg2 and msg4*/
		if (msg_cnt == 1) {
			/*message 2*/
			TRY(_memcpy_s(data, *data_len, m.m2, m.m2_len));
			*data_len = m.m2_len;
			msg_cnt++;
		} else {
			/*message 4*/
			TRY(_memcpy_s(data, *data_len, m.m4, m.m4_len));
			*data_len = m.m4_len;
			msg_cnt = 1;
		}
	} else {
		PRINTF("TXRX wrapper test vectors\n");

		/*The responder must get msg1 and msg3*/
		if (msg_cnt == 1) {
			/*message 1 */
			TRY(_memcpy_s(data, *data_len, m.m1, m.m1_len));
			*data_len = m.m1_len;
			msg_cnt++;
		} else {
			/*message 3*/
			TRY(_memcpy_s(data, *data_len, m.m3, m.m3_len));
			*data_len = m.m3_len;
			msg_cnt = 1;
		}
	}
	return ok;
}

enum err tx(void *sock, uint8_t *data, uint32_t data_len)
{ //todo add here a test
	return ok;
}
