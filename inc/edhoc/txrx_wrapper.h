/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef EDHOC_TXRX_WRAPPER_H
#define EDHOC_TXRX_WRAPPER_H

#include "common/byte_array.h"

/**
 * @brief                       The user should call inside this function its 
 *                              send function. 
 * 
 * @param[in] data                  Pointer to the data to be send.
 * @param data_len              Length of the data.
 * @retval                      Or or error code.
 */
extern enum err tx(uint8_t *data, uint32_t data_len);

/**
 * @brief                       The user should call inside this function its 
 *                              receive function. The length of the buffer 
 *                              pointed by data can be checked before 
 *                              copying data into it by using *data_len. 
 *                              After copying the length of the received data 
 *                              should be written in data_len.
 * 
 * @param[out] data             Pointer to a buffer where the edhoc 
 *                              message must be copied.
 * @param[out] data_len         Length of the received data.
 * @retval                      Or or error code.
 */
extern enum err rx(uint8_t *data, uint32_t *data_len);

#endif
