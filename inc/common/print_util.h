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
 *@brief			Prints an array for debug purposes.
 *@param[in] in_data		The array to be printed.
 *@param in_len			The length of the array.
 */
void print_array(const uint8_t *in_data, uint32_t in_len);

/**
 * @brief 			In case of an error this function prints where 
 * 				the error occurred.
 * 
 * @param error_code 		The error code to be printed.
 * @param file_name 		The file name where the error occurred.
 * @param line 			The line at which the error occurred.
 */
void handle_runtime_error(int error_code, const char *file_name,
			  const int line);
		
/**
 * @brief 			In case of an error in a function belonging to 
 * 				an external library this function prints where 
 * 				the error occurred.
 * 
 * @param error_code 		The error code to be printed.
 * @param file_name 		The file name where the error occurred.
 * @param line 			The line at which the error occurred.
 */		
void handle_external_runtime_error(int error_code, const char *file_name,
				   const int line);
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
