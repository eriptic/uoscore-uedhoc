/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef OSCORE_TESTS_H
#define OSCORE_TESTS_H

/*integration tests*/
void t1_oscore_client_request_response(void);
void t3_oscore_client_request(void);
void t5_oscore_client_request(void);
void t2_oscore_server_request_response(void);
void t4_oscore_server_key_derivation(void);
void t6_oscore_server_key_derivation(void);
void t8_oscore_server_response_simple_ack(void);
void t9_oscore_client_server_registration_two_notifications_cancellation(void);


/*unit tests*/
void t100_inner_outer_option_split__no_special_options(void);
void t101_inner_outer_option_split__with_observe_notification(void);
void t102_inner_outer_option_split__with_observe_registration(void);
void t103_oscore_pkg_generate__request_with_observe_registration(void);
void t104_oscore_pkg_generate__request_with_observe_notification(void);
#endif