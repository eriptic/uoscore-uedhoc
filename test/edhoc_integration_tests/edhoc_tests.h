/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef EDHOC_TESTS_H
#define EDHOC_TESTS_H

#include <stdint.h>
//#include "../../samples/common/test_vec_parser.h"

struct messages {
	uint8_t *m1;
	uint32_t m1_len;
	uint8_t *m2;
	uint32_t m2_len;
	uint8_t *m3;
	uint32_t m3_len;
	uint8_t *m4;
	uint32_t m4_len;
};

//extern struct messages_bufs m_bufs;
extern struct messages m;

/**
 * @brief       Test EDHOC initiator according to RFC9529 Section 2.
 *              Authentication with Signatures, X.509 Identified by 'x5t'
 */
void test_edhoc_initiator_x509_x5t_rfc9529();
/**
 * @brief       Test EDHOC initiator according to RFC9529 Section 2.
 *              Authentication with Signatures, X.509 Identified by 'x5t'
 */
void test_edhoc_responder_x509_x5t_rfc9529();

/**
 * @brief       Test EDHOC initiator according to RFC9529 Section 3.
 *              Static DH authentication, CCS identified by 'kid'.
 */
void test_edhoc_initiator_static_dh_kid_rfc9529();

/**
 * @brief       Test EDHOC responder according to RFC9529 Section 3.
 *              Static DH authentication, CCS identified by 'kid'.
 */
void test_edhoc_responder_static_dh_kid_rfc9529();

/**
 * @brief       Tests the compact encoding of a 'kid' in id_cred2kid().
 */
void t_kid_id_cred2kid(void);

/**
 * @brief       Tests the reconstruction of ID_CRED_x from a 'kid' in
 *              plaintext_split().
 */
void t_kid_plaintext_split(void);

/**
 * @brief       Tests the credential lookup with RFC 9528 and int 'kid's.
 */
void t_kid_retrieve_cred(void);

/**
 * @brief 		Tests the functions of the exporter interface
 */
void test_exporter(void);

/**
 * @brief 		Executes an instance of a responder and a initiator in 
 * 				parallel and checks if the results are the same. This test is 
 * 				especially relevant for ECC suites, e.g. P256 since signatures 
 * 				created with such suites are non-deterministic and therefore it 
 * 				is not possible to run only one of the party and to compare the 
 * 				results with pre computed values.  
 * @param		vec_num the test vector number
 */
void test_initiator_responder_interaction(int vec_num);

void t_initiator_responder_interaction1();
void t_initiator_responder_interaction2();
#endif