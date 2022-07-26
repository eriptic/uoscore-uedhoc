/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef PRINT_UTIL_H
#define PRINT_UTIL_H

#include <stdint.h>
#include <stdio.h>
/**
 *@brief prints an array for debug pourposes 
 */
void print_array(const uint8_t *in_data, uint32_t in_len);

#ifdef DEBUG_PRINT
#define PRINT_ARRAY(msg, a, a_len)                                             \
	printf(msg);                                                           \
	print_array(a, a_len);
#define PRINT_MSG(msg) printf(msg);
#define PRINTF(f_, ...) printf((f_), ##__VA_ARGS__);
#else
#define PRINT_ARRAY(msg, a, a_len) {};
#define PRINT_MSG(msg) {};
#define PRINTF(f_, ...) {};
#endif

#endif
