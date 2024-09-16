/*
 * Generated using zcbor version 0.8.99
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_DECODE_PLAINTEXT3_TYPES_H__
#define EDHOC_DECODE_PLAINTEXT3_TYPES_H__

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

struct map3_kid_r {
	union {
		int32_t map3_kid_int;
		struct zcbor_string map3_kid_bstr;
	};
	enum {
		map3_kid_int_c,
		map3_kid_bstr_c,
	} map3_kid_choice;
};

struct map3_x5bag {
	struct zcbor_string map3_x5bag;
};

struct map3_x5chain {
	struct zcbor_string map3_x5chain;
};

struct map3_x5t_r {
	union {
		int32_t map3_x5t_alg_int;
		struct zcbor_string map3_x5t_alg_tstr;
	};
	enum {
		map3_x5t_alg_int_c,
		map3_x5t_alg_tstr_c,
	} map3_x5t_alg_choice;
	struct zcbor_string map3_x5t_hash;
};

struct map3_x5u {
	struct zcbor_string map3_x5u;
};

struct map3_c5b {
	struct zcbor_string map3_c5b;
};

struct map3_c5c {
	struct zcbor_string map3_c5c;
};

struct map3_c5t_r {
	union {
		int32_t map3_c5t_alg_int;
		struct zcbor_string map3_c5t_alg_tstr;
	};
	enum {
		map3_c5t_alg_int_c,
		map3_c5t_alg_tstr_c,
	} map3_c5t_alg_choice;
	struct zcbor_string map3_c5t_hash;
};

struct map3_c5u {
	struct zcbor_string map3_c5u;
};

struct map3 {
	struct map3_kid_r map3_kid;
	bool map3_kid_present;
	struct map3_x5bag map3_x5bag;
	bool map3_x5bag_present;
	struct map3_x5chain map3_x5chain;
	bool map3_x5chain_present;
	struct map3_x5t_r map3_x5t;
	bool map3_x5t_present;
	struct map3_x5u map3_x5u;
	bool map3_x5u_present;
	struct map3_c5b map3_c5b;
	bool map3_c5b_present;
	struct map3_c5c map3_c5c;
	bool map3_c5c_present;
	struct map3_c5t_r map3_c5t;
	bool map3_c5t_present;
	struct map3_c5u map3_c5u;
	bool map3_c5u_present;
};

struct ptxt3 {
	union {
		struct map3 ptxt3_ID_CRED_I_map3_m;
		struct zcbor_string ptxt3_ID_CRED_I_bstr;
		int32_t ptxt3_ID_CRED_I_int;
	};
	enum {
		ptxt3_ID_CRED_I_map3_m_c,
		ptxt3_ID_CRED_I_bstr_c,
		ptxt3_ID_CRED_I_int_c,
	} ptxt3_ID_CRED_I_choice;
	struct zcbor_string ptxt3_SGN_or_MAC_3;
	struct zcbor_string ptxt3_EAD_3;
	bool ptxt3_EAD_3_present;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_DECODE_PLAINTEXT3_TYPES_H__ */
