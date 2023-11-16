/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef ERROR_H
#define ERROR_H
#include "print_util.h"

/* All possible errors that EDHOC and OSCORE can have */
enum err {
	/*common errors*/
	ok = 0,
	buffer_to_small = 1,
	hkdf_failed = 2,
	unexpected_result_from_ext_lib = 3,
	wrong_parameter = 4,
	crypto_operation_not_implemented = 5,
	not_supported_feature = 6,
	/*indicates that transport layer is not initialized*/
	transport_deinitialized = 7,
	not_implemented = 8,
	vla_insufficient_size = 9,


	/*EDHOC specific errors*/
	/*todo implement error messages*/
	error_message_received = 101,
	error_message_sent = 102,

	sign_failed = 103,
	sha_failed = 104,

	unsupported_cipher_suite = 106,
	unsupported_ecdh_curve = 107,
	unsupported_signature_algorithm = 110,

	signature_authentication_failed = 112,
	mac_authentication_failed = 113,
	certificate_authentication_failed = 115,

	credential_not_found = 116,
	no_such_ca = 117,

	cbor_encoding_error = 119,
	cbor_decoding_error = 120,
	suites_i_list_to_long = 121,
	xor_error = 122,
        suites_i_list_empty = 123,

	/*OSCORE specific errors*/
	not_oscore_pkt = 200,
	first_request_after_reboot = 201,
	echo_validation_failed = 202,
	oscore_unknown_hkdf = 203,
	token_mismatch = 204,
	oscore_invalid_algorithm_aead = 205,
	oscore_invalid_algorithm_hkdf = 206,
	oscore_kid_recipient_id_mismatch = 207,
	too_many_options = 208,
	oscore_valuelen_to_long_error = 209,
	oscore_inpkt_invalid_tkl = 210,
	oscore_inpkt_invalid_option_delta = 211,
	oscore_inpkt_invalid_optionlen = 212,
	oscore_inpkt_invalid_piv = 213,
	not_valid_input_packet = 214,
	oscore_replay_window_protection_error = 215,
	oscore_replay_notification_protection_error = 216,
	no_echo_option = 217,
	echo_val_mismatch = 218,
	oscore_ssn_overflow = 219,
	oscore_max_interactions = 220,
	oscore_interaction_duplicated_token = 221,
	oscore_interaction_not_found = 222,
	oscore_wrong_uri_path = 223,
};

/*This macro checks if a function returns an error and if so it propagates 
	the error to the caller function*/
#define TRY(x)                                                                 \
	do {                                                                   \
		enum err retval = (x);                                         \
		if (ok != retval) {                                            \
			handle_runtime_error(retval, __FILE__, __LINE__);      \
			return retval;                                         \
		}                                                              \
	} while (0)

/* This macro checks if a function belonging to an external library returns an expected result or an error. If an error is returned the macro returns unexpected_result_from_ext_lib. */
#define TRY_EXPECT(x, expected_result)                                         \
	do {                                                                   \
		int retval = (x);                                              \
		if (retval != expected_result) {                               \
			handle_external_runtime_error(retval, __FILE__,        \
						      __LINE__);               \
			return unexpected_result_from_ext_lib;                 \
		}                                                              \
	} while (0)

#endif
