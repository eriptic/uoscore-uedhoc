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

struct const_byte_array {
	uint32_t len;
	const uint8_t *ptr;
};

/* Empty Array with len=0 but with a non-null pointer.*/
extern struct byte_array EMPTY_ARRAY;

/* Null Array with len=0 and a null pointer.*/
extern struct byte_array NULL_ARRAY;

/**
 * @brief			Compares if the given two arrays have equal
 * 				content.
 *
 * @param[in] a 		Array "a".
 * @param[in] b 		Array "b".
 * @return  			True if the contents of both arrays is equal.
 */
bool array_equals(const struct byte_array *a, const struct byte_array *b);

/**
 * @brief 			Creates a copy of a byte array.
 * 
 * @param[out] dest 		The destination byte array.
 * @param[in] src		The source byte array. 
 * @param dest_max_len 		The maximal length of the destination array.
 * @return enum err 		Ok or error code.
 */
enum err byte_array_cpy(struct byte_array *dest, const struct byte_array *src,
			const uint32_t dest_max_len);

/**
 * @brief   			Initializes a byte array variable with a 
 * 				pointer to a buffer and length of the buffer.
 *
 * @param PTR			pointer
 * @param LEN			Length of the buffer in bytes 
 */
#define BYTE_ARRAY_INIT(PTR, LEN)                                              \
	{                                                                      \
		.len = LEN, .ptr = PTR                                         \
	}

/**
 * @brief   Creates a variable of type byte_array.
 *          In addition a buffer is created to hold the data.
 *          If Variable Length Array (VLA) is NOT used, before the creation of 
 *          the buffer it is checked if the size of the buffer (BUF_SIZE) will 
 *          be sufficient for the size of the byte_array (SIZE). 
*/
#ifdef VLA
#define BYTE_ARRAY_NEW(NAME, BUF_SIZE, SIZE)                                   \
	if (SIZE < 0 || SIZE > BUF_SIZE) {                                     \
		return vla_insufficient_size;                                  \
	}                                                                      \
	struct byte_array NAME;                                                \
	uint8_t NAME##_buf[SIZE];                                              \
	if (SIZE == 0) {                                                       \
		NAME = NULL_ARRAY;                                             \
	} else {                                                               \
		NAME.ptr = NAME##_buf;                                         \
		NAME.len = SIZE;                                               \
	};

#else
#define BYTE_ARRAY_NEW(NAME, BUF_SIZE, SIZE)                                   \
	TRY(check_buffer_size(BUF_SIZE, SIZE));                                \
	struct byte_array NAME;                                                \
	uint8_t NAME##_buf[BUF_SIZE];                                          \
	if (SIZE == 0) {                                                       \
		NAME = NULL_ARRAY;                                             \
	} else {                                                               \
		NAME.ptr = NAME##_buf;                                         \
		NAME.len = SIZE;                                               \
	};
#endif

#endif //BYTE_ARRAY_H
