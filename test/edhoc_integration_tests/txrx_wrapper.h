/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef TXRX_WRAPPER_H
#define TXRX_WRAPPER_H
#include "edhoc.h"

extern bool rx_initiator_switch;
enum err rx(void *sock, uint8_t *data, uint32_t *data_len);
enum err tx(void *sock, uint8_t *data, uint32_t data_len);
void rx_init(void);
#endif