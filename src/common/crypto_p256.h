/*
 * Support for EC point decompression on secp256r1 curve.
 *
 * PSA API do not support parsing of EC compressed points (at least not up to
 * specs release 1.4), but this functionality is required from the uoscore-uedhoc
 * library. However since it only need to handle secp256r1 curves and that
 * Mbed TLS has a special full software library (p256-m) for this curve, relevant
 * math functions are copied from there and "crypto_p256_uncompress_point()" is
 * added to get allow EC point decompression.
 *
 * Copyright BayLibre SAS
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#ifndef CRYPTO_P256_M_H
#define CRYPTO_P256_M_H

#ifdef MBEDTLS

#include <stdint.h>

int crypto_p256_uncompress_point(const uint8_t *input, size_t ilen,
				 uint8_t *output, size_t *olen, size_t osize);

#endif /* MBEDTLS */

#endif /* CRYPTO_P256_M_H */
