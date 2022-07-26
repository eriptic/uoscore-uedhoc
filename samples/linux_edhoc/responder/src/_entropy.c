#include <stddef.h>

/* IMPORTANT! PROVIDE HERE A REAL ENTROPY! */
int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len,
			  size_t *olen)
{
	(void)data;

	if (output == NULL) {
		return -1;
	}

	if (olen == NULL) {
		return -1;
	}

	if (len == 0) {
		return -1;
	}

	/*We don't get real random numbers*/
	for (size_t i = 0; i < len; i++) {
		output[i] = i;
	}

	*olen = len;

	return 0;
}