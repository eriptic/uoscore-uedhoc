
#ifndef INT_ENCODE_DECODE_H
#define INT_ENCODE_DECODE_H

#include <stdint.h>
#include "common/oscore_edhoc_error.h"

enum err decode_int(uint8_t *in, uint32_t in_len, int32_t *out);
enum err encode_int(const int32_t *in, uint32_t in_len, uint8_t *out,
		    uint32_t *out_len);
#endif