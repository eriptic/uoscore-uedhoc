/*
   Copyright (c) 2022 Eriptic Technologies. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#ifndef UNIT_TEST_H
#define UNIT_TEST_H

#include "byte_array.h"

#include "oscore/oscore_coap.h"
#include "oscore/security_context.h"

/*when UNIT_TEST is defined all static functions are not static anymore and 
can be used in unit test files.*/
#if UNIT_TEST
#define STATIC

/*the prototypes of all static functions that are used in unit tests*/
enum err inner_outer_option_split(struct o_coap_packet *in_o_coap,
				  struct o_coap_option *e_options,
				  uint8_t *e_options_cnt,
				  uint16_t *e_options_len,
				  struct o_coap_option *U_options,
				  uint8_t *U_options_cnt);

enum err oscore_pkg_generate(struct o_coap_packet *in_o_coap,
			     struct o_coap_packet *out_oscore,
			     struct o_coap_option *u_options,
			     uint8_t u_options_cnt,
			     struct byte_array *in_ciphertext,
			     struct oscore_option *oscore_option);

enum err oscore_option_parser(const struct o_coap_option *opt, uint8_t opt_cnt,
			      struct compressed_oscore_option *out);

enum err options_reorder(struct o_coap_option *U_options, uint8_t U_options_cnt,
			 struct o_coap_option *E_options, uint8_t E_options_cnt,
			 struct o_coap_option *out_options,
			 uint8_t *out_options_cnt);

enum err oscore_option_generate(struct byte_array *piv, struct byte_array *kid,
				struct byte_array *kid_context,
				struct oscore_option *oscore_option);

enum err derive(struct common_context *cc, struct byte_array *id,
		enum derive_type type, struct byte_array *out);

#else
#define STATIC static
#endif

#endif