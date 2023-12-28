#include <zephyr/kernel.h>
#include <zephyr/device.h>
#include <zephyr/drivers/entropy.h>
#include <mbedtls/entropy.h>
#include <entropy_poll.h>

int mbedtls_hardware_poll(void *data, unsigned char *output, size_t len,
			  size_t *olen)
{
	// const struct device *dev;
	// size_t chunk_size;

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

	// dev = device_get_binding(DT_CHOSEN_ZEPHYR_ENTROPY_LABEL);

	// if (!dev) {
	// 	return MBEDTLS_ERR_ENTROPY_NO_SOURCES_DEFINED;
	// }

	// while (len > 0) {
	// 	chunk_size = MIN(MBEDTLS_ENTROPY_MAX_GATHER, len);

	// 	if (entropy_get_entropy(dev, output, chunk_size) < 0) {
	// 		return MBEDTLS_ERR_ENTROPY_SOURCE_FAILED;
	// 	}

	// 	*olen += chunk_size;
	// 	output += chunk_size;
	// 	len -= chunk_size;
	// }

	/*We don't get real random numbers*/
	for (size_t i = 0; i < len; i++) {
		output[i] = i;
	}

	*olen = len;

	return 0;
}

#if defined(unix) || defined(__linux__) || defined(__unix__) ||                \
	defined(__unix) | (defined(__APPLE__) && defined(__MACH__)) ||         \
	defined(uECC_POSIX)
/*use the entropy source as provided in /tinycrypt/lib/source/ecc_platform_specific.c*/
#else
int default_CSPRNG(uint8_t *dest, unsigned int size)
{
	return 1;
}
#endif