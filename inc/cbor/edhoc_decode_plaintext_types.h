/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_DECODE_PLAINTEXT_TYPES_H__
#define EDHOC_DECODE_PLAINTEXT_TYPES_H__

#include <stdint.h>
#include <stdbool.h>
#include <stddef.h>
#include <zcbor_common.h>

#ifdef __cplusplus
extern "C" {
#endif

/** Which value for --default-max-qty this file was created with.
 *
 *  The define is used in the other generated file to do a build-time
 *  compatibility check.
 *
 *  See `zcbor --help` for more information about --default-max-qty
 */
#define DEFAULT_MAX_QTY 3

struct map_kid_r {
	union {
		int32_t map_kid_int;
		struct zcbor_string map_kid_bstr;
	};
	enum {
		map_kid_int_c,
		map_kid_bstr_c,
	} map_kid_choice;
};

struct map_x5bag {
	struct zcbor_string map_x5bag;
};

struct map_x5chain {
	struct zcbor_string map_x5chain;
};

struct map_x5t_r {
	union {
		int32_t map_x5t_alg_int;
		struct zcbor_string map_x5t_alg_tstr;
	};
	enum {
		map_x5t_alg_int_c,
		map_x5t_alg_tstr_c,
	} map_x5t_alg_choice;
	struct zcbor_string map_x5t_hash;
};

struct map_x5u {
	struct zcbor_string map_x5u;
};

struct map_c5b {
	struct zcbor_string map_c5b;
};

struct map_c5c {
	struct zcbor_string map_c5c;
};

struct map_c5t_r {
	union {
		int32_t map_c5t_alg_int;
		struct zcbor_string map_c5t_alg_tstr;
	};
	enum {
		map_c5t_alg_int_c,
		map_c5t_alg_tstr_c,
	} map_c5t_alg_choice;
	struct zcbor_string map_c5t_hash;
};

struct map_c5u {
	struct zcbor_string map_c5u;
};

struct map {
	struct map_kid_r map_kid;
	bool map_kid_present;
	struct map_x5bag map_x5bag;
	bool map_x5bag_present;
	struct map_x5chain map_x5chain;
	bool map_x5chain_present;
	struct map_x5t_r map_x5t;
	bool map_x5t_present;
	struct map_x5u map_x5u;
	bool map_x5u_present;
	struct map_c5b map_c5b;
	bool map_c5b_present;
	struct map_c5c map_c5c;
	bool map_c5c_present;
	struct map_c5t_r map_c5t;
	bool map_c5t_present;
	struct map_c5u map_c5u;
	bool map_c5u_present;
};

struct plaintext {
	union {
		struct map plaintext_ID_CRED_x_map_m;
		struct zcbor_string plaintext_ID_CRED_x_bstr;
		int32_t plaintext_ID_CRED_x_int;
	};
	enum {
		plaintext_ID_CRED_x_map_m_c,
		plaintext_ID_CRED_x_bstr_c,
		plaintext_ID_CRED_x_int_c,
	} plaintext_ID_CRED_x_choice;
	struct zcbor_string plaintext_SGN_or_MAC_x;
	struct zcbor_string plaintext_AD_x;
	bool plaintext_AD_x_present;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_DECODE_PLAINTEXT_TYPES_H__ */
