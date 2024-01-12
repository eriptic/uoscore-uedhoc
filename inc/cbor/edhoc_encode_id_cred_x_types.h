/*
 * Generated using zcbor version 0.8.0
 * https://github.com/NordicSemiconductor/zcbor
 * Generated with a --default-max-qty of 3
 */

#ifndef EDHOC_ENCODE_ID_CRED_X_TYPES_H__
#define EDHOC_ENCODE_ID_CRED_X_TYPES_H__

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

struct id_cred_x_map_kid_r {
	union {
		int32_t id_cred_x_map_kid_int;
		struct zcbor_string id_cred_x_map_kid_bstr;
	};
	enum {
		id_cred_x_map_kid_int_c,
		id_cred_x_map_kid_bstr_c,
	} id_cred_x_map_kid_choice;
};

struct id_cred_x_map_x5bag {
	struct zcbor_string id_cred_x_map_x5bag;
};

struct id_cred_x_map_x5chain {
	struct zcbor_string id_cred_x_map_x5chain;
};

struct id_cred_x_map_x5t_r {
	union {
		int32_t id_cred_x_map_x5t_alg_int;
		struct zcbor_string id_cred_x_map_x5t_alg_tstr;
	};
	enum {
		id_cred_x_map_x5t_alg_int_c,
		id_cred_x_map_x5t_alg_tstr_c,
	} id_cred_x_map_x5t_alg_choice;
	struct zcbor_string id_cred_x_map_x5t_hash;
};

struct id_cred_x_map_x5u {
	struct zcbor_string id_cred_x_map_x5u;
};

struct id_cred_x_map_c5b {
	struct zcbor_string id_cred_x_map_c5b;
};

struct id_cred_x_map_c5c {
	struct zcbor_string id_cred_x_map_c5c;
};

struct id_cred_x_map_c5t_r {
	union {
		int32_t id_cred_x_map_c5t_alg_int;
		struct zcbor_string id_cred_x_map_c5t_alg_tstr;
	};
	enum {
		id_cred_x_map_c5t_alg_int_c,
		id_cred_x_map_c5t_alg_tstr_c,
	} id_cred_x_map_c5t_alg_choice;
	struct zcbor_string id_cred_x_map_c5t_hash;
};

struct id_cred_x_map_c5u {
	struct zcbor_string id_cred_x_map_c5u;
};

struct id_cred_x_map {
	struct id_cred_x_map_kid_r id_cred_x_map_kid;
	bool id_cred_x_map_kid_present;
	struct id_cred_x_map_x5bag id_cred_x_map_x5bag;
	bool id_cred_x_map_x5bag_present;
	struct id_cred_x_map_x5chain id_cred_x_map_x5chain;
	bool id_cred_x_map_x5chain_present;
	struct id_cred_x_map_x5t_r id_cred_x_map_x5t;
	bool id_cred_x_map_x5t_present;
	struct id_cred_x_map_x5u id_cred_x_map_x5u;
	bool id_cred_x_map_x5u_present;
	struct id_cred_x_map_c5b id_cred_x_map_c5b;
	bool id_cred_x_map_c5b_present;
	struct id_cred_x_map_c5c id_cred_x_map_c5c;
	bool id_cred_x_map_c5c_present;
	struct id_cred_x_map_c5t_r id_cred_x_map_c5t;
	bool id_cred_x_map_c5t_present;
	struct id_cred_x_map_c5u id_cred_x_map_c5u;
	bool id_cred_x_map_c5u_present;
};

#ifdef __cplusplus
}
#endif

#endif /* EDHOC_ENCODE_ID_CRED_X_TYPES_H__ */
