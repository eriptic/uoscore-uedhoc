/*
 * Copyright (c) 2023 Eriptic Technologies
 *
 * SPDX-License-Identifier: Apache-2.0 or MIT
 */

#ifndef LATENCY_H
#define LATENCY_H

#include <zephyr/kernel.h>
#include <zephyr/sys/time_units.h>

#ifdef MEASURE_LATENCY_ON
#define MEASURE_LATENCY(x)                                                     \
	do {                                                                   \
		volatile uint32_t clock_start = k_cycle_get_32();              \
		int32_t r = (x);                                               \
		volatile uint32_t clock_end = k_cycle_get_32();                \
		volatile uint32_t cycles = clock_end - clock_start;            \
		volatile uint64_t us = k_cyc_to_us_near64(cycles);             \
		printf("Elapsed time:  %d (RTC cycles); %lld (us)\n", cycles,    \
		       us);                                                    \
		if (0 != r) {                                                  \
			printf("An Error has ocurred! Error code: %d\n", r);   \
		}                                                              \
	} while (0)
#else
#define MEASURE_LATENCY(x)                                                     \
	do {                                                                   \
		int32_t r = (x);                                               \
		if (0 != r) {                                                  \
			printf("An Error has ocurred! Error code: %d\n", r);   \
		}                                                              \
	} while (0)
#endif /*MEASURE_LATENCY_ON*/

#endif /*LATENCY_H*/
