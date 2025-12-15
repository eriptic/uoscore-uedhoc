/*
 * Support for EC point decompression on secp256r1 curve.
 *
 * Copyright The Mbed TLS Contributors (for all math functions)
 * Author: Manuel Pégourié-Gonnard.
 *
 * Copyright BayLibre SAS (for crypto_p256_uncompress_point())
 *
 * SPDX-License-Identifier: Apache-2.0 OR GPL-2.0-or-later
 */

#include <psa/crypto.h>
#include <edhoc/buffer_sizes.h>
#include "crypto_p256.h"


/**********************************************************************
 *
 * Operations on fixed-width unsigned integers
 *
 * Represented using 32-bit limbs, least significant limb first.
 * That is: x = x[0] + 2^32 x[1] + ... + 2^224 x[7] for 256-bit.
 *
 **********************************************************************/

/*
 * 256-bit set to 32-bit value
 *
 * in: x in [0, 2^32)
 * out: z = x
 */
static void u256_set32(uint32_t z[8], uint32_t x)
{
	z[0] = x;
	for (unsigned i = 1; i < 8; i++) {
		z[i] = 0;
	}
}

/*
 * 256-bit addition
 *
 * in: x, y in [0, 2^256)
 * out: z = (x + y) mod 2^256
 *      c = (x + y) div 2^256
 * That is, z + c * 2^256 = x + y
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 */
static uint32_t u256_add(uint32_t z[8],
						 const uint32_t x[8], const uint32_t y[8])
{
	uint32_t carry = 0;

	for (unsigned i = 0; i < 8; i++) {
		uint64_t sum = (uint64_t) carry + x[i] + y[i];
		z[i] = (uint32_t) sum;
		carry = (uint32_t) (sum >> 32);
	}

	return carry;
}

/*
 * 256-bit subtraction
 *
 * in: x, y in [0, 2^256)
 * out: z = (x - y) mod 2^256
 *      c = 0 if x >=y, 1 otherwise
 * That is, z = c * 2^256 + x - y
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 */
static uint32_t u256_sub(uint32_t z[8],
						 const uint32_t x[8], const uint32_t y[8])
{
	uint32_t carry = 0;

	for (unsigned i = 0; i < 8; i++) {
		uint64_t diff = (uint64_t) x[i] - y[i] - carry;
		z[i] = (uint32_t) diff;
		carry = -(uint32_t) (diff >> 32);
	}

	return carry;
}

/*
 * 256-bit conditional assignment
 *
 * in: x in [0, 2^256)
 *     c in [0, 1]
 * out: z = x if c == 1, z unchanged otherwise
 *
 * Note: as a memory area, z must be either equal to x, or not overlap.
 */
static void u256_cmov(uint32_t z[8], const uint32_t x[8], uint32_t c)
{
	const uint32_t x_mask = -c;
	for (unsigned i = 0; i < 8; i++) {
		z[i] = (z[i] & ~x_mask) | (x[i] & x_mask);
	}
}

/*
 * 256-bit compare for equality
 *
 * in: x in [0, 2^256)
 *     y in [0, 2^256)
 * out: 0 if x == y, unspecified non-zero otherwise
 */
static uint32_t u256_diff(const uint32_t x[8], const uint32_t y[8])
{
	uint32_t diff = 0;
	for (unsigned i = 0; i < 8; i++) {
		diff |= x[i] ^ y[i];
	}
	return diff;
}

/*
 * 32 x 32 -> 64-bit multiply-and-accumulate
 *
 * in: x, y, z, t in [0, 2^32)
 * out: x * y + z + t in [0, 2^64)
 *
 * Note: this computation cannot overflow.
 *
 * Note: this function has two pure-C implementations (depending on whether
 * MUL64_IS_CONSTANT_TIME), and possibly optimised asm implementations.
 * Start with the potential asm definitions, and use the C definition only if
 * we no have no asm for the current toolchain & CPU.
 */
static uint64_t u32_muladd64(uint32_t x, uint32_t y, uint32_t z, uint32_t t);

/* This macro is used to mark whether an asm implentation is found */
#undef MULADD64_ASM
/* This macro is used to mark whether the implementation has a small
 * code size (ie, it can be inlined even in an unrolled loop) */
#undef MULADD64_SMALL

/*
 * Currently assembly optimisations are only supported with GCC/Clang for
 * Arm's Cortex-A and Cortex-M lines of CPUs, which start with the v6-M and
 * v7-M architectures. __ARM_ARCH_PROFILE is not defined for v6 and earlier.
 * Thumb and 32-bit assembly is supported; aarch64 is not supported.
 */
#if defined(__GNUC__) &&\
	defined(__ARM_ARCH) && __ARM_ARCH >= 6 && defined(__ARM_ARCH_PROFILE) && \
	( __ARM_ARCH_PROFILE == 77 || __ARM_ARCH_PROFILE == 65 ) /* 'M' or 'A' */ && \
	!defined(__aarch64__)

/*
 * This set of CPUs is conveniently partitioned as follows:
 *
 * 1. Cores that have the DSP extension, which includes a 1-cycle UMAAL
 *    instruction: M4, M7, M33, all A-class cores.
 * 2. Cores that don't have the DSP extension, and also lack a constant-time
 *    64-bit multiplication instruction:
 *    - M0, M0+, M23: 32-bit multiplication only;
 *    - M3: 64-bit multiplication is not constant-time.
 */
#if defined(__ARM_FEATURE_DSP)

static uint64_t u32_muladd64(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
{
	__asm__(
		/* UMAAL <RdLo>, <RdHi>, <Rn>, <Rm> */
		"umaal   %[z], %[t], %[x], %[y]"
		: [z] "+l" (z), [t] "+l" (t)
		: [x] "l" (x), [y] "l" (y)
	);
	return ((uint64_t) t << 32) | z;
}
#define MULADD64_ASM
#define MULADD64_SMALL

#else /* __ARM_FEATURE_DSP */

/*
 * This implementation only uses 16x16->32 bit multiplication.
 *
 * It decomposes the multiplicands as:
 *      x = xh:xl = 2^16 * xh + xl
 *      y = yh:yl = 2^16 * yh + yl
 * and computes their product as:
 *      x*y = xl*yl + 2**16 (xh*yl + yl*yh) + 2**32 xh*yh
 * then adds z and t to the result.
 */
static uint64_t u32_muladd64(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
{
	/* First compute x*y, using 3 temporary registers */
	uint32_t tmp1, tmp2, tmp3;
	__asm__(
		".syntax unified\n\t"
		/* start by splitting the inputs into halves */
		"lsrs    %[u], %[x], #16\n\t"
		"lsrs    %[v], %[y], #16\n\t"
		"uxth    %[x], %[x]\n\t"
		"uxth    %[y], %[y]\n\t"
		/* now we have %[x], %[y], %[u], %[v] = xl, yl, xh, yh */
		/* let's compute the 4 products we can form with those */
		"movs    %[w], %[v]\n\t"
		"muls    %[w], %[u]\n\t"
		"muls    %[v], %[x]\n\t"
		"muls    %[x], %[y]\n\t"
		"muls    %[y], %[u]\n\t"
		/* now we have %[x], %[y], %[v], %[w] = xl*yl, xh*yl, xl*yh, xh*yh */
		/* let's split and add the first middle product */
		"lsls    %[u], %[y], #16\n\t"
		"lsrs    %[y], %[y], #16\n\t"
		"adds    %[x], %[u]\n\t"
		"adcs    %[y], %[w]\n\t"
		/* let's finish with the second middle product */
		"lsls    %[u], %[v], #16\n\t"
		"lsrs    %[v], %[v], #16\n\t"
		"adds    %[x], %[u]\n\t"
		"adcs    %[y], %[v]\n\t"
		: [x] "+l" (x), [y] "+l" (y),
		  [u] "=&l" (tmp1), [v] "=&l" (tmp2), [w] "=&l" (tmp3)
		: /* no read-only inputs */
		: "cc"
	);
	(void) tmp1;
	(void) tmp2;
	(void) tmp3;

	/* Add z and t, using one temporary register */
	__asm__(
		".syntax unified\n\t"
		"movs    %[u], #0\n\t"
		"adds    %[x], %[z]\n\t"
		"adcs    %[y], %[u]\n\t"
		"adds    %[x], %[t]\n\t"
		"adcs    %[y], %[u]\n\t"
		: [x] "+l" (x), [y] "+l" (y), [u] "=&l" (tmp1)
		: [z] "l" (z), [t] "l" (t)
		: "cc"
	);
	(void) tmp1;

	return ((uint64_t) y << 32) | x;
}
#define MULADD64_ASM

#endif /* __ARM_FEATURE_DSP */

#endif /* GCC/Clang with Cortex-M/A CPU */

#if !defined(MULADD64_ASM)
#if defined(MUL64_IS_CONSTANT_TIME)
static uint64_t u32_muladd64(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
{
	return (uint64_t) x * y + z + t;
}
#define MULADD64_SMALL
#else
static uint64_t u32_muladd64(uint32_t x, uint32_t y, uint32_t z, uint32_t t)
{
	/* x = xl + 2**16 xh, y = yl + 2**16 yh */
	const uint16_t xl = (uint16_t) x;
	const uint16_t yl = (uint16_t) y;
	const uint16_t xh = x >> 16;
	const uint16_t yh = y >> 16;

	/* x*y = xl*yl + 2**16 (xh*yl + yl*yh) + 2**32 xh*yh
	 *     = lo    + 2**16 (m1    + m2   ) + 2**32 hi    */
	const uint32_t lo = (uint32_t) xl * yl;
	const uint32_t m1 = (uint32_t) xh * yl;
	const uint32_t m2 = (uint32_t) xl * yh;
	const uint32_t hi = (uint32_t) xh * yh;

	uint64_t acc = lo + ((uint64_t) (hi + (m1 >> 16) + (m2 >> 16)) << 32);
	acc += m1 << 16;
	acc += m2 << 16;
	acc += z;
	acc += t;

	return acc;
}
#endif /* MUL64_IS_CONSTANT_TIME */
#endif /* MULADD64_ASM */

/*
 * 288 + 32 x 256 -> 288-bit multiply and add
 *
 * in: x in [0, 2^32)
 *     y in [0, 2^256)
 *     z in [0, 2^288)
 * out: z_out = z_in + x * y mod 2^288
 *      c     = z_in + x * y div 2^288
 * That is, z_out + c * 2^288 = z_in + x * y
 *
 * Note: as a memory area, z must be either equal to y, or not overlap.
 *
 * This is a helper for Montgomery multiplication.
 */
static uint32_t u288_muladd(uint32_t z[9], uint32_t x, const uint32_t y[8])
{
	uint32_t carry = 0;

#define U288_MULADD_STEP(i) \
	do { \
		uint64_t prod = u32_muladd64(x, y[i], z[i], carry); \
		z[i] = (uint32_t) prod; \
		carry = (uint32_t) (prod >> 32); \
	} while( 0 )

#if defined(MULADD64_SMALL)
	U288_MULADD_STEP(0);
	U288_MULADD_STEP(1);
	U288_MULADD_STEP(2);
	U288_MULADD_STEP(3);
	U288_MULADD_STEP(4);
	U288_MULADD_STEP(5);
	U288_MULADD_STEP(6);
	U288_MULADD_STEP(7);
#else
	for (unsigned i = 0; i < 8; i++) {
		U288_MULADD_STEP(i);
	}
#endif

	uint64_t sum = (uint64_t) z[8] + carry;
	z[8] = (uint32_t) sum;
	carry = (uint32_t) (sum >> 32);

	return carry;
}

/*
 * 288-bit in-place right shift by 32 bits
 *
 * in: z in [0, 2^288)
 *     c in [0, 2^32)
 * out: z_out = z_in div 2^32 + c * 2^256
 *            = (z_in + c * 2^288) div 2^32
 *
 * This is a helper for Montgomery multiplication.
 */
static void u288_rshift32(uint32_t z[9], uint32_t c)
{
	for (unsigned i = 0; i < 8; i++) {
		z[i] = z[i + 1];
	}
	z[8] = c;
}

/*
 * 256-bit import from big-endian bytes
 *
 * in: p = p0, ..., p31
 * out: z = p0 * 2^248 + p1 * 2^240 + ... + p30 * 2^8 + p31
 */
static void u256_from_bytes(uint32_t z[8], const uint8_t p[32])
{
	for (unsigned i = 0; i < 8; i++) {
		unsigned j = 4 * (7 - i);
		z[i] = ((uint32_t) p[j + 0] << 24) |
			   ((uint32_t) p[j + 1] << 16) |
			   ((uint32_t) p[j + 2] <<  8) |
			   ((uint32_t) p[j + 3] <<  0);
	}
}

/*
 * 256-bit export to big-endian bytes
 *
 * in: z in [0, 2^256)
 * out: p = p0, ..., p31 such that
 *      z = p0 * 2^248 + p1 * 2^240 + ... + p30 * 2^8 + p31
 */
static void u256_to_bytes(uint8_t p[32], const uint32_t z[8])
{
	for (unsigned i = 0; i < 8; i++) {
		unsigned j = 4 * (7 - i);
		p[j + 0] = (uint8_t) (z[i] >> 24);
		p[j + 1] = (uint8_t) (z[i] >> 16);
		p[j + 2] = (uint8_t) (z[i] >>  8);
		p[j + 3] = (uint8_t) (z[i] >>  0);
	}
}

/**********************************************************************
 *
 * Operations modulo a 256-bit prime m
 *
 * These are done in the Montgomery domain, that is x is represented by
 *  x * 2^256 mod m
 * Numbers need to be converted to that domain before computations,
 * and back from it afterwards.
 *
 * Inversion is computed using Fermat's little theorem.
 *
 * Assumptions on m:
 * - Montgomery operations require that m is odd.
 * - Fermat's little theorem require it to be a prime.
 * - m256_inv() further requires that m % 2^32 >= 2.
 * - m256_inv() also assumes that the value of m is not a secret.
 *
 * In practice operations are done modulo the curve's p and n,
 * both of which satisfy those assumptions.
 *
 **********************************************************************/

/*
 * Data associated to a modulus for Montgomery operations.
 *
 * m in [0, 2^256) - the modulus itself, must be odd
 * R2 = 2^512 mod m
 * ni = -m^-1 mod 2^32
 */
typedef struct {
	uint32_t m[8];
	uint32_t R2[8];
	uint32_t ni;
}
m256_mod;

/*
 * Data for Montgomery operations modulo the curve's p
 */
static const m256_mod p256_p = {
	{   /* the curve's p */
		0xFFFFFFFF, 0xFFFFFFFF, 0xFFFFFFFF, 0x00000000,
		0x00000000, 0x00000000, 0x00000001, 0xFFFFFFFF,
	},
	{   /* 2^512 mod p */
		0x00000003, 0x00000000, 0xffffffff, 0xfffffffb,
		0xfffffffe, 0xffffffff, 0xfffffffd, 0x00000004,
	},
	0x00000001, /* -p^-1 mod 2^32 */
};

/*
 * Modular addition
 *
 * in: x, y in [0, m)
 *     mod must point to a valid m256_mod structure
 * out: z = (x + y) mod m, in [0, m)
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 */
static void m256_add(uint32_t z[8],
					 const uint32_t x[8], const uint32_t y[8],
					 const m256_mod *mod)
{
	uint32_t r[8];
	uint32_t carry_add = u256_add(z, x, y);
	uint32_t carry_sub = u256_sub(r, z, mod->m);
	/* Need to subract m if:
	 *      x+y >= 2^256 > m (that is, carry_add == 1)
	 *   OR z >= m (that is, carry_sub == 0) */
	uint32_t use_sub = carry_add | (1 - carry_sub);
	u256_cmov(z, r, use_sub);
}

/*
 * Modular addition mod p
 *
 * in: x, y in [0, p)
 * out: z = (x + y) mod p, in [0, p)
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 */
static void m256_add_p(uint32_t z[8],
					   const uint32_t x[8], const uint32_t y[8])
{
	m256_add(z, x, y, &p256_p);
}

/*
 * Modular subtraction
 *
 * in: x, y in [0, m)
 *     mod must point to a valid m256_mod structure
 * out: z = (x - y) mod m, in [0, m)
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 */
static void m256_sub(uint32_t z[8],
					 const uint32_t x[8], const uint32_t y[8],
					 const m256_mod *mod)
{
	uint32_t r[8];
	uint32_t carry = u256_sub(z, x, y);
	(void) u256_add(r, z, mod->m);
	/* Need to add m if and only if x < y, that is carry == 1.
	 * In that case z is in [2^256 - m + 1, 2^256 - 1], so the
	 * addition will have a carry as well, which cancels out. */
	u256_cmov(z, r, carry);
}

/*
 * Modular subtraction mod p
 *
 * in: x, y in [0, p)
 * out: z = (x + y) mod p, in [0, p)
 *
 * Note: as a memory area, z must be either equal to x or y, or not overlap.
 */
static void m256_sub_p(uint32_t z[8],
					   const uint32_t x[8], const uint32_t y[8])
{
	m256_sub(z, x, y, &p256_p);
}

/*
 * Montgomery modular multiplication
 *
 * in: x, y in [0, m)
 *     mod must point to a valid m256_mod structure
 * out: z = (x * y) / 2^256 mod m, in [0, m)
 *
 * Note: as a memory area, z may overlap with x or y.
 */
static void m256_mul(uint32_t z[8],
					 const uint32_t x[8], const uint32_t y[8],
					 const m256_mod *mod)
{
	/*
	 * Algorithm 14.36 in Handbook of Applied Cryptography with:
	 * b = 2^32, n = 8, R = 2^256
	 */
	uint32_t m_prime = mod->ni;
	uint32_t a[9];

	for (unsigned i = 0; i < 9; i++) {
		a[i] = 0;
	}

	for (unsigned i = 0; i < 8; i++) {
		/* the "mod 2^32" is implicit from the type */
		uint32_t u = (a[0] + x[i] * y[0]) * m_prime;

		/* a = (a + x[i] * y + u * m) div b */
		uint32_t c = u288_muladd(a, x[i], y);
		c += u288_muladd(a, u, mod->m);
		u288_rshift32(a, c);
	}

	/* a = a > m ? a - m : a */
	uint32_t carry_add = a[8];  // 0 or 1 since a < 2m, see HAC Note 14.37
	uint32_t carry_sub = u256_sub(z, a, mod->m);
	uint32_t use_sub = carry_add | (1 - carry_sub);     // see m256_add()
	u256_cmov(z, a, 1 - use_sub);
}

/*
 * Montgomery modular multiplication modulo p.
 *
 * in: x, y in [0, p)
 * out: z = (x * y) / 2^256 mod p, in [0, p)
 *
 * Note: as a memory area, z may overlap with x or y.
 */
static void m256_mul_p(uint32_t z[8],
					   const uint32_t x[8], const uint32_t y[8])
{
	m256_mul(z, x, y, &p256_p);
}

/*
 * In-place conversion to Montgomery form
 *
 * in: z in [0, m)
 *     mod must point to a valid m256_mod structure
 * out: z_out = z_in * 2^256 mod m, in [0, m)
 */
static void m256_prep(uint32_t z[8], const m256_mod *mod)
{
	m256_mul(z, z, mod->R2, mod);
}

/*
 * In-place conversion from Montgomery form
 *
 * in: z in [0, m)
 *     mod must point to a valid m256_mod structure
 * out: z_out = z_in / 2^256 mod m, in [0, m)
 * That is, z_in was z_actual * 2^256 mod m, and z_out is z_actual
 */
static void m256_done(uint32_t z[8], const m256_mod *mod)
{
	uint32_t one[8];
	u256_set32(one, 1);
	m256_mul(z, z, one, mod);
}

/*
 * Set to 32-bit value
 *
 * in: x in [0, 2^32)
 *     mod must point to a valid m256_mod structure
 * out: z = x * 2^256 mod m, in [0, m)
 * That is, z is set to the image of x in the Montgomery domain.
 */
static void m256_set32(uint32_t z[8], uint32_t x, const m256_mod *mod)
{
	u256_set32(z, x);
	m256_prep(z, mod);
}

/*
 * Modular inversion in Montgomery form
 *
 * in: x in [0, m)
 *     mod must point to a valid m256_mod structure
 *     such that mod->m % 2^32 >= 2, assumed to be public.
 * out: z = x^-1 * 2^512 mod m if x != 0,
 *      z = 0 if x == 0
 * That is, if x = x_actual    * 2^256 mod m, then
 *             z = x_actual^-1 * 2^256 mod m
 *
 * Note: as a memory area, z may overlap with x.
 */
static void m256_inv(uint32_t z[8], const uint32_t x[8],
					 const m256_mod *mod)
{
	/*
	 * Use Fermat's little theorem to compute x^-1 as x^(m-2).
	 *
	 * Take advantage of the fact that both p's and n's least significant limb
	 * is at least 2 to perform the subtraction on the flight (no carry).
	 *
	 * Use plain right-to-left binary exponentiation;
	 * branches are OK as the exponent is not a secret.
	 */
	uint32_t bitval[8];
	u256_cmov(bitval, x, 1);    /* copy x before writing to z */

	m256_set32(z, 1, mod);

	unsigned i = 0;
	uint32_t limb = mod->m[i] - 2;
	while (1) {
		for (unsigned j = 0; j < 32; j++) {
			if ((limb & 1) != 0) {
				m256_mul(z, z, bitval, mod);
			}
			m256_mul(bitval, bitval, bitval, mod);
			limb >>= 1;
		}

		if (i == 7)
			break;

		i++;
		limb = mod->m[i];
	}
}

/*
 * Import modular integer from bytes to Montgomery domain
 *
 * in: p = p0, ..., p32
 *     mod must point to a valid m256_mod structure
 * out: z = (p0 * 2^248 + ... + p31) * 2^256 mod m, in [0, m)
 *      return 0 if the number was already in [0, m), or -1.
 *      z may be incorrect and must be discared when -1 is returned.
 */
static int m256_from_bytes(uint32_t z[8],
						   const uint8_t p[32], const m256_mod *mod)
{
	u256_from_bytes(z, p);

	uint32_t t[8];
	uint32_t lt_m = u256_sub(t, z, mod->m);
	if (lt_m != 1)
		return -1;

	m256_prep(z, mod);
	return 0;
}

/*
 * Export modular integer from Montgomery domain to bytes
 *
 * in: z in [0, 2^256)
 *     mod must point to a valid m256_mod structure
 * out: p = p0, ..., p31 such that
 *      z = (p0 * 2^248 + ... + p31) * 2^256 mod m
 */
static void m256_to_bytes(uint8_t p[32],
						  const uint32_t z[8], const m256_mod *mod)
{
	uint32_t zi[8];
	u256_cmov(zi, z, 1);
	m256_done(zi, mod);

	u256_to_bytes(p, zi);
}

/**********************************************************************
 *
 * Operations on curve points
 *
 * Points are represented in two coordinates system:
 *  - affine (x, y) - extended to represent 0 (see below)
 *  - jacobian (x:y:z)
 * In either case, coordinates are integers modulo p256_p and
 * are always represented in the Montgomery domain.
 *
 * For background on jacobian coordinates, see for example [GECC] 3.2.2:
 * - conversions go (x, y) -> (x:y:1) and (x:y:z) -> (x/z^2, y/z^3)
 * - the curve equation becomes y^2 = x^3 - 3 x z^4 + b z^6
 * - 0 (aka the origin aka point at infinity) is (x:y:0) with y^2 = x^3.
 * - point negation goes -(x:y:z) = (x:-y:z)
 *
 * Normally 0 (the point at infinity) can't be represented in affine
 * coordinates. However we extend affine coordinates with the convention that
 * (0, 0) (which is normally not a point on the curve) is interpreted as 0.
 *
 * References:
 * - [GECC]: Guide to Elliptic Curve Cryptography; Hankerson, Menezes,
 *   Vanstone; Springer, 2004.
 * - [CMO98]: Efficient Elliptic Curve Exponentiation Using Mixed Coordinates;
 *   Cohen, Miyaji, Ono; Springer, ASIACRYPT 1998.
 *   https://link.springer.com/content/pdf/10.1007/3-540-49649-1_6.pdf
 * - [RCB15]: Complete addition formulas for prime order elliptic curves;
 *   Renes, Costello, Batina; IACR e-print 2015-1060.
 *   https://eprint.iacr.org/2015/1060.pdf
 *
 **********************************************************************/

/*
 * The curve's b parameter in the Short Weierstrass equation
 *  y^2 = x^3 - 3*x + b
 * Compared to the standard, this is converted to the Montgomery domain.
 */
static const uint32_t p256_b[8] = { /* b * 2^256 mod p */
	0x29c4bddf, 0xd89cdf62, 0x78843090, 0xacf005cd,
	0xf7212ed6, 0xe5a220ab, 0x04874834, 0xdc30061d,
};

/*
 * Point-on-curve check - do the coordinates satisfy the curve's equation?
 *
 * in: x, y in [0, p)   (Montgomery domain)
 * out: 0 if the point lies on the curve and is not 0,
 *      unspecified non-zero otherwise
 */
static uint32_t point_check(const uint32_t x[8], const uint32_t y[8])
{
	uint32_t lhs[8], rhs[8];

	/* lhs = y^2 */
	m256_mul_p(lhs, y, y);

	/* rhs = x^3 - 3x + b */
	m256_mul_p(rhs, x,   x);      /* x^2 */
	m256_mul_p(rhs, rhs, x);      /* x^3 */
	for (unsigned i = 0; i < 3; i++)
		m256_sub_p(rhs, rhs, x);  /* x^3 - 3x */
	m256_add_p(rhs, rhs, p256_b); /* x^3 - 3x + b */

	return u256_diff(lhs, rhs);
}

/*
 * Import curve point from bytes
 *
 * in: p = (x, y) concatenated, fixed-width 256-bit big-endian integers
 * out: x, y in Mongomery domain
 *      return 0 if x and y are both in [0, p)
 *                  and (x, y) is on the curve and not 0
 *             unspecified non-zero otherwise.
 *      x and y are unspecified and must be discarded if returning non-zero.
 */
static int point_from_bytes(uint32_t x[8], uint32_t y[8], const uint8_t p[64])
{
	int ret;

	ret = m256_from_bytes(x, p, &p256_p);
	if (ret != 0)
		return ret;

	ret = m256_from_bytes(y, p + 32, &p256_p);
	if (ret != 0)
		return ret;

	return (int) point_check(x, y);
}

int crypto_p256_uncompress_point(const uint8_t *input, size_t ilen,
				 uint8_t *output, size_t *olen, size_t osize)
{
	uint32_t x[8], r[8], y2[8];
	int ret;

	if (ilen != 32) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	if (osize < 65) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	// output will consist of 0x04|X|Y
	*olen = 65;
	output[0] = 0x04;

	// x <= input
	if (m256_from_bytes(x, input, &p256_p) != 0) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	/* r = x^3 - 3x + b */
	m256_mul_p(r, x, x); /* x^2 */
	m256_mul_p(r, r, x); /* x^3 */
	for (unsigned int i = 0; i < 3; i++)
		m256_sub_p(r, r, x); /* x^3 - 3x */
	m256_add_p(r, r, p256_b); /* x^3 - 3x + b */
	/* y^2 = r */
	u256_cmov(y2, r, 1);

	/* exp = (p + 1)/4 = (p + 1) >> 2 */
	uint32_t exp[8] = {
		0x00000000, 0x00000000, 0x40000000, 0x00000000,
		0x00000000, 0x40000000, 0xC0000000, 0x3FFFFFFF
	};

	/* Binary exponentiation */
	m256_set32(r, 1, &p256_p);
	for (uint32_t i = 0; i < 8; i++) {
		uint32_t exp_limb = exp[i];
		for (uint32_t j = 0; j < 32; j++) {
			if (exp_limb & 1) {
				m256_mul_p(r, r, y2);
			}
			m256_mul_p(y2, y2, y2);
			exp_limb >>= 1;
		}
	}

	uint32_t y[8], zero[8];
	u256_set32(zero, 0);
	/* y = r */
	u256_cmov(y, r, 1);

	uint8_t y_raw[32];
	m256_to_bytes(y_raw, y, &p256_p);

	uint8_t p[64];
	uint32_t x_check[8], y_check[8];
	memcpy(p, input, 32);
	memcpy(p + 32, y_raw, 32);
	ret = point_from_bytes(x_check, y_check, p);
	if (ret != 0) {
		return PSA_ERROR_INVALID_ARGUMENT;
	}

	memcpy(output + 1, p, 64);

	return 0;
}
