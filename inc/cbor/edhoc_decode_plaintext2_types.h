/*
 * Generated using zcbor version 0.8.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_DECODE_PLAINTEXT2_TYPES_H__
#define EDHOC_DECODE_PLAINTEXT2_TYPES_H__

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

struct map2_kid_r {
	union {
		int32_t map2_kid_int;
		struct zcbor_string map2_kid_bstr;
	};
	enum {
		map2_kid_int_c,
		map2_kid_bstr_c,
	} map2_kid_choice;
};

struct map2_x5bag {
	struct zcbor_string map2_x5bag;
};

struct map2_x5chain {
	struct zcbor_string map2_x5chain;
};

struct map2_x5t_r {
	union {
		int32_t map2_x5t_alg_int;
		struct zcbor_string map2_x5t_alg_tstr;
	};
	enum {
		map2_x5t_alg_int_c,
		map2_x5t_alg_tstr_c,
	} map2_x5t_alg_choice;
	struct zcbor_string map2_x5t_hash;
};

struct map2_x5u {
	struct zcbor_string map2_x5u;
};

struct map2_c5b {
	struct zcbor_string map2_c5b;
};

struct map2_c5c {
	struct zcbor_string map2_c5c;
};

struct map2_c5t_r {
	union {
		int32_t map2_c5t_alg_int;
		struct zcbor_string map2_c5t_alg_tstr;
	};
	enum {
		map2_c5t_alg_int_c,
		map2_c5t_alg_tstr_c,
	} map2_c5t_alg_choice;
	struct zcbor_string map2_c5t_hash;
};

struct map2_c5u {
	struct zcbor_string map2_c5u;
};

struct map2 {
	struct map2_kid_r map2_kid;
	bool map2_kid_present;
	struct map2_x5bag map2_x5bag;
	bool map2_x5bag_present;
	struct map2_x5chain map2_x5chain;
	bool map2_x5chain_present;
	struct map2_x5t_r map2_x5t;
	bool map2_x5t_present;
	struct map2_x5u map2_x5u;
	bool map2_x5u_present;
	struct map2_c5b map2_c5b;
	bool map2_c5b_present;
	struct map2_c5c map2_c5c;
	bool map2_c5c_present;
	struct map2_c5t_r map2_c5t;
	bool map2_c5t_present;
	struct map2_c5u map2_c5u;
	bool map2_c5u_present;
};

struct ptxt2 {
	union {
		int32_t ptxt2_C_R_int;
		struct zcbor_string ptxt2_C_R_bstr;
	};
	enum {
		ptxt2_C_R_int_c,
		ptxt2_C_R_bstr_c,
	} ptxt2_C_R_choice;
	union {
		struct map2 ptxt2_ID_CRED_R_map2_m;
		struct zcbor_string ptxt2_ID_CRED_R_bstr;
		int32_t ptxt2_ID_CRED_R_int;
	};
	enum {
		ptxt2_ID_CRED_R_map2_m_c,
		ptxt2_ID_CRED_R_bstr_c,
		ptxt2_ID_CRED_R_int_c,
	} ptxt2_ID_CRED_R_choice;
	struct zcbor_string ptxt2_SGN_or_MAC_2;
	struct zcbor_string ptxt2_EAD_2;
	bool ptxt2_EAD_2_present;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_DECODE_PLAINTEXT2_TYPES_H__ */
