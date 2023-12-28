/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdint.h>
#include <stdio.h>

#include "common/print_util.h"
#include "common/oscore_edhoc_error.h"
#include "common/print_util.h"

void print_array(const uint8_t *in_data, uint32_t in_len)
{
	printf(" (size %lu):", (unsigned long)in_len);
	if (NULL != in_data) {
		for (uint32_t i = 0; i < in_len; i++) {
			if (i % 16 == 0)
				printf("\n\t%02X ", in_data[i]);
			else
				printf("%02X ", in_data[i]);
		}
	}
	printf("\n");
}

void handle_runtime_error(int error_code, const char *file_name, const int line)
{
	(void)error_code;
	(void)file_name;
	(void)line;

#ifdef DEBUG_PRINT
	if (transport_deinitialized == error_code) {
		PRINTF(transport_deinit_message, file_name, line);
	} else {
		PRINTF(runtime_error_message, error_code, file_name, line);
	}
#endif
}

void handle_external_runtime_error(int error_code, const char *file_name,
				   const int line)
{
	(void)error_code;
	(void)file_name;
	(void)line;

#ifdef DEBUG_PRINT
	PRINTF(external_runtime_error_message, error_code, file_name, line);
#endif
}
