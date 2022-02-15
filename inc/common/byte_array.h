/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef BYTE_ARRAY_H
#define BYTE_ARRAY_H

#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/* Array with pointer and length.*/
struct byte_array {
	uint32_t len;
	uint8_t *ptr;
};

/* Empty Array with len=0 but with a non-null pointer.*/
extern struct byte_array EMPTY_ARRAY;

/* Null Array with len=0 and a null pointer.*/
extern struct byte_array NULL_ARRAY;

/**
 * @brief Initializes a variable of type byte_array
 * 
 * @param buf buffer containing the data
 * @param buf_len the lenhgt of the buffer
 * @param byte_array the byte_array variable to be initialized
 */
void byte_array_init(uint8_t *buf, uint32_t buf_len,
		     struct byte_array *byte_array);

/**
 * @brief   Compares if the given two arrays have an equal content.
 *
 *          Handles null-arrays correctly
 * @param   left first array
 * @param   right second array
 * @return  if the contents of given arrays are equal
 */
bool array_equals(const struct byte_array *left,
		  const struct byte_array *right);

#endif
