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

#include "oscore_edhoc_error.h"
#include "memcpy_s.h"

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
 * @brief   Compares if the given two arrays have an equal content.
 *
 *          Handles null-arrays correctly
 * @param   left first array
 * @param   right second array
 * @return  if the contents of given arrays are equal
 */
bool array_equals(const struct byte_array *left,
		  const struct byte_array *right);

enum err byte_array_cpy(struct byte_array *dest, const struct byte_array *src,
			const uint32_t dest_max_len);

/**
 * @brief   Sets the pointer and the length of a byte_array variable to a given array
*/
#define BYTE_ARRAY_INIT(PTR, SIZE) { .ptr = PTR, .len = SIZE }

/**
 * @brief   Creates a variable of type byte_array.
 *          In addition a buffer is created to hold the data.
 *          Before the creation of the buffer it is checked if the size of the 
 *          buffer (BUF_SIZE) will be sufficient for the size of the byte_array 
 *          (SIZE). 
*/
#define BYTE_ARRAY_NEW(NAME, BUF_SIZE, SIZE)                                   \
	TRY(check_buffer_size(BUF_SIZE, SIZE));                                \
	uint8_t NAME##_buf[BUF_SIZE];                                          \
	struct byte_array NAME = BYTE_ARRAY_INIT(NAME##_buf, SIZE);

#endif
