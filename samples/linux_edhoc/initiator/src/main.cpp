/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <arpa/inet.h>
#include <netinet/in.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

extern "C" {
#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"
#include "edhoc_test_vectors_rfc9529.h"
}
#include "cantcoap.h"

#define USE_IPV4
//#define USE_IPV6
/*comment this out to use DH keys from the test vectors*/
#define USE_RANDOM_EPHEMERAL_DH_KEY

/**
 * @brief	Initializes sockets for CoAP client.
 * @param
 * @retval	error code
 */
static int start_coap_client(int *sockfd)
{
	int err;
#ifdef USE_IPV4
	struct sockaddr_in servaddr;
	//const char IPV4_SERVADDR[] = { "127.0.0.1" };
	//const char IPV4_SERVADDR[] = { "128.93.85.146" };
	//const char IPV4_SERVADDR[] = { "128.93.85.216" };
	const char IPV4_SERVADDR[] = { "16.171.132.249" };
	err = sock_init(SOCK_CLIENT, IPV4_SERVADDR, IPv4, &servaddr,
			sizeof(servaddr), sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif
#ifdef USE_IPV6
	struct sockaddr_in6 servaddr;
	const char IPV6_SERVADDR[] = { "2001:db8::1" };
	err = sock_init(SOCK_CLIENT, IPV6_SERVADDR, IPv6, &servaddr,
			sizeof(servaddr), sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif
	return 0;
}

enum err ead_process(void *params, struct byte_array *ead13)
{
	/*for this sample we are not using EAD*/
	/*to save RAM we use FEATURES += -DEAD_SIZE=0*/
	return ok;
}

/**
 * @brief	Callback function called inside the frontend when data needs to 
 * 		be send over the network. We use here CoAP as transport 
 * @param	data pointer to the data that needs to be send
 */
enum err tx(void *sock, struct byte_array *data)
{
	/*construct a CoAP packet*/
	static uint16_t mid = 0;
	static uint32_t token = 0;
	CoapPDU *pdu = new CoapPDU();
	pdu->reset();
	pdu->setVersion(1);
	pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	pdu->setCode(CoapPDU::COAP_POST);
	pdu->setToken((uint8_t *)&(++token), sizeof(token));
	pdu->setMessageID(mid++);
	pdu->setURI((char *)".well-known/edhoc", 17);
	pdu->setPayload(data->ptr, data->len);

	const void *data_ptr = pdu->getPDUPointer();
	size_t len = pdu->getPDULength();

	send(*((int *)sock), data_ptr, len, 0);

	delete pdu;
	return ok;
}

/**
 * @brief	Callback function called inside the frontend when data needs to 
 * 		be received over the network. We use here CoAP as transport 
 * @param	data pointer to the data that needs to be received
 */
enum err rx(void *sock, struct byte_array *data)
{
	int n;
	char buffer[MAXLINE];
	CoapPDU *recvPDU;
	/* receive */
	n = recv(*((int *)sock), (char *)buffer, MAXLINE, MSG_WAITALL);
	if (n < 0) {
		printf("recv error");
	}

	recvPDU = new CoapPDU((uint8_t *)buffer, n);

	if (recvPDU->validate()) {
		//recvPDU->printHuman();
	}

	uint32_t payload_len = recvPDU->getPayloadLength();
	//printf("data_len: %d\n", data->len);
	//printf("payload_len: %d\n", payload_len);

	if (data->len >= payload_len) {
		memcpy(data->ptr, recvPDU->getPayloadPointer(), payload_len);
		data->len = payload_len;
	} else {
		printf("insufficient space in buffer");
		return buffer_to_small;
	}

	delete recvPDU;
	return ok;
}

#ifdef MARCO

/*own (initiator) credentials*/
uint8_t SUITES_I[] = { 0 };
uint8_t CRED_I[] = { 0x54, 0x13, 0x20, 0x4c, 0x3e, 0xbc, 0x34, 0x28, 0xa6, 0xcf,
		     0x57, 0xe2, 0x4c, 0x9d, 0xef, 0x59, 0x65, 0x17, 0x70, 0x44,
		     0x9b, 0xce, 0x7e, 0xc6, 0x56, 0x1e, 0x52, 0x43, 0x3a, 0xa5,
		     0x5e, 0x71, 0xf1, 0xfa, 0x34, 0xb2, 0x2a, 0x9c, 0xa4, 0xa1,
		     0xe1, 0x29, 0x24, 0xea, 0xe1, 0xd1, 0x76, 0x60, 0x88, 0x09,
		     0x84, 0x49, 0xcb, 0x84, 0x8f, 0xfc, 0x79, 0x5f, 0x88, 0xaf,
		     0xc4, 0x9c, 0xbe, 0x8a, 0xfd, 0xd1, 0xba, 0x00, 0x9f, 0x21,
		     0x67, 0x5e, 0x8f, 0x6c, 0x77, 0xa4, 0xa2, 0xc3, 0x01, 0x95,
		     0x60, 0x1f, 0x6f, 0x0a, 0x08, 0x52, 0x97, 0x8b, 0xd4, 0x3d,
		     0x28, 0x20, 0x7d, 0x44, 0x48, 0x65, 0x02, 0xff, 0x7b, 0xdd,
		     0xa6 };
uint8_t ID_CRED_I[] = {
	0xa1, 0x18, 0x21, 0x58, 0x65, 0x54, 0x13, 0x20, 0x4c, 0x3e, 0xbc, 0x34,
	0x28, 0xa6, 0xcf, 0x57, 0xe2, 0x4c, 0x9d, 0xef, 0x59, 0x65, 0x17, 0x70,
	0x44, 0x9b, 0xce, 0x7e, 0xc6, 0x56, 0x1e, 0x52, 0x43, 0x3a, 0xa5, 0x5e,
	0x71, 0xf1, 0xfa, 0x34, 0xb2, 0x2a, 0x9c, 0xa4, 0xa1, 0xe1, 0x29, 0x24,
	0xea, 0xe1, 0xd1, 0x76, 0x60, 0x88, 0x09, 0x84, 0x49, 0xcb, 0x84, 0x8f,
	0xfc, 0x79, 0x5f, 0x88, 0xaf, 0xc4, 0x9c, 0xbe, 0x8a, 0xfd, 0xd1, 0xba,
	0x00, 0x9f, 0x21, 0x67, 0x5e, 0x8f, 0x6c, 0x77, 0xa4, 0xa2, 0xc3, 0x01,
	0x95, 0x60, 0x1f, 0x6f, 0x0a, 0x08, 0x52, 0x97, 0x8b, 0xd4, 0x3d, 0x28,
	0x20, 0x7d, 0x44, 0x48, 0x65, 0x02, 0xff, 0x7b, 0xdd, 0xa6
};

uint8_t PK_I[] = { 0x38, 0xe5, 0xd5, 0x45, 0x63, 0xc2, 0xb6, 0xa4,
		   0xba, 0x26, 0xf3, 0x01, 0x5f, 0x61, 0xbb, 0x70,
		   0x6e, 0x5c, 0x2e, 0xfd, 0xb5, 0x56, 0xd2, 0xe1,
		   0x69, 0x0b, 0x97, 0xfc, 0x3c, 0x6d, 0xe1, 0x49 };
uint8_t SK_I[] = { 0x2f, 0xfc, 0xe7, 0xa0, 0xb2, 0xb8, 0x25, 0xd3,
		   0x97, 0xd0, 0xcb, 0x54, 0xf7, 0x46, 0xe3, 0xda,
		   0x3f, 0x27, 0x59, 0x6e, 0xe0, 0x6b, 0x53, 0x71,
		   0x48, 0x1d, 0xc0, 0xe0, 0x12, 0xbc, 0x34, 0xd7 };

/*responder credentials*/
uint8_t PK_R[] = { 0xdb, 0xd9, 0xdc, 0x8c, 0xd0, 0x3f, 0xb7, 0xc3,
		   0x91, 0x35, 0x11, 0x46, 0x2b, 0xb2, 0x38, 0x16,
		   0x47, 0x7c, 0x6b, 0xd8, 0xd6, 0x6e, 0xf5, 0xa1,
		   0xa0, 0x70, 0xac, 0x85, 0x4e, 0xd7, 0x3f, 0xd2 };

uint8_t CRED_R[] = {
	0xc7, 0x88, 0x37, 0x00, 0x16, 0xb8, 0x96, 0x5b, 0xdb, 0x20, 0x74, 0xbf,
	0xf8, 0x2e, 0x5a, 0x20, 0xe0, 0x9b, 0xec, 0x21, 0xf8, 0x40, 0x6e, 0x86,
	0x44, 0x2b, 0x87, 0xec, 0x3f, 0xf2, 0x45, 0xb7, 0x0a, 0x47, 0x62, 0x4d,
	0xc9, 0xcd, 0xc6, 0x82, 0x4b, 0x2a, 0x4c, 0x52, 0xe9, 0x5e, 0xc9, 0xd6,
	0xb0, 0x53, 0x4b, 0x71, 0xc2, 0xb4, 0x9e, 0x4b, 0xf9, 0x03, 0x15, 0x00,
	0xce, 0xe6, 0x86, 0x99, 0x79, 0xc2, 0x97, 0xbb, 0x5a, 0x8b, 0x38, 0x1e,
	0x98, 0xdb, 0x71, 0x41, 0x08, 0x41, 0x5e, 0x5c, 0x50, 0xdb, 0x78, 0x97,
	0x4c, 0x27, 0x15, 0x79, 0xb0, 0x16, 0x33, 0xa3, 0xef, 0x62, 0x71, 0xbe,
	0x5c, 0x22, 0x5e, 0xb2
};

#endif

int main()
{
	int sockfd;
	BYTE_ARRAY_NEW(prk_exporter, 32, 32);
	BYTE_ARRAY_NEW(oscore_master_secret, 16, 16);
	BYTE_ARRAY_NEW(oscore_master_salt, 8, 8);
	BYTE_ARRAY_NEW(PRK_out, 32, 32);
	BYTE_ARRAY_NEW(err_msg, 0, 0);

	/* test vector inputs */
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

#define ORIG
#ifdef ORIG

	uint8_t TEST_VEC_NUM = 1;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	c_i.sock = &sockfd;
	c_i.c_i.len = test_vectors[vec_num_i].c_i_len;
	c_i.c_i.ptr = (uint8_t *)test_vectors[vec_num_i].c_i;
	c_i.method = (enum method_type) * test_vectors[vec_num_i].method;
	c_i.suites_i.len = test_vectors[vec_num_i].SUITES_I_len;
	c_i.suites_i.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_I;
	c_i.ead_1.len = test_vectors[vec_num_i].ead_1_len;
	c_i.ead_1.ptr = (uint8_t *)test_vectors[vec_num_i].ead_1;
	c_i.ead_3.len = test_vectors[vec_num_i].ead_3_len;
	c_i.ead_3.ptr = (uint8_t *)test_vectors[vec_num_i].ead_3;
	c_i.id_cred_i.len = test_vectors[vec_num_i].id_cred_i_len;
	c_i.id_cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	c_i.cred_i.len = test_vectors[vec_num_i].cred_i_len;
	c_i.cred_i.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	c_i.g_x.len = test_vectors[vec_num_i].g_x_raw_len;
	c_i.g_x.ptr = (uint8_t *)test_vectors[vec_num_i].g_x_raw;
	c_i.x.len = test_vectors[vec_num_i].x_raw_len;
	c_i.x.ptr = (uint8_t *)test_vectors[vec_num_i].x_raw;
	c_i.g_i.len = test_vectors[vec_num_i].g_i_raw_len;
	c_i.g_i.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	c_i.i.len = test_vectors[vec_num_i].i_raw_len;
	c_i.i.ptr = (uint8_t *)test_vectors[vec_num_i].i_raw;
	c_i.sk_i.len = test_vectors[vec_num_i].sk_i_raw_len;
	c_i.sk_i.ptr = (uint8_t *)test_vectors[vec_num_i].sk_i_raw;
	c_i.pk_i.len = test_vectors[vec_num_i].pk_i_raw_len;
	c_i.pk_i.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;

	cred_r.id_cred.len = test_vectors[vec_num_i].id_cred_r_len;
	cred_r.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	cred_r.cred.len = test_vectors[vec_num_i].cred_r_len;
	cred_r.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	cred_r.g.len = test_vectors[vec_num_i].g_r_raw_len;
	cred_r.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	cred_r.pk.len = test_vectors[vec_num_i].pk_r_raw_len;
	cred_r.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;
	cred_r.ca.len = test_vectors[vec_num_i].ca_r_len;
	cred_r.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r;
	cred_r.ca_pk.len = test_vectors[vec_num_i].ca_r_pk_len;
	cred_r.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_r_pk;
#endif

#ifdef CHRISTIAN
	c_i.sock = &sockfd;
	c_i.c_i.len = T1_RFC9529__C_I_LEN;
	c_i.c_i.ptr = (uint8_t *)T1_RFC9529__C_I;
	c_i.method = (enum method_type)T1_RFC9529__METHOD;
	c_i.suites_i.len = T1_RFC9529__SUITES_I_LEN;
	c_i.suites_i.ptr = (uint8_t *)T1_RFC9529__SUITES_I;
	c_i.ead_1.len = 0;
	c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0;
	c_i.ead_3.ptr = NULL;
	c_i.id_cred_i.len = T1_RFC9529__ID_CRED_I_LEN;
	c_i.id_cred_i.ptr = (uint8_t *)T1_RFC9529__ID_CRED_I;
	c_i.cred_i.len = T1_RFC9529__CRED_I_LEN;
	c_i.cred_i.ptr = (uint8_t *)T1_RFC9529__CRED_I;
	c_i.g_x.len = T1_RFC9529__G_X_LEN;
	c_i.g_x.ptr = (uint8_t *)T1_RFC9529__G_X;
	c_i.x.len = T1_RFC9529__X_LEN;
	c_i.x.ptr = (uint8_t *)T1_RFC9529__X;
	c_i.g_i.len = 0;
	c_i.g_i.ptr = NULL;
	c_i.i.len = 0;
	c_i.i.ptr = NULL;
	c_i.sk_i.len = T1_RFC9529__SK_I_LEN;
	c_i.sk_i.ptr = (uint8_t *)T1_RFC9529__SK_I;
	c_i.pk_i.len = T1_RFC9529__PK_I_LEN;
	c_i.pk_i.ptr = (uint8_t *)T1_RFC9529__PK_I;

	cred_r.id_cred.len = T1_RFC9529__ID_CRED_R_LEN;
	cred_r.id_cred.ptr = (uint8_t *)T1_RFC9529__ID_CRED_R;
	cred_r.cred.len = T1_RFC9529__CRED_R_LEN;
	cred_r.cred.ptr = (uint8_t *)T1_RFC9529__CRED_R;
	cred_r.g.len = 0;
	cred_r.g.ptr = NULL;
	cred_r.pk.len = T1_RFC9529__PK_R_LEN;
	cred_r.pk.ptr = (uint8_t *)T1_RFC9529__PK_R;
	cred_r.ca.len = 0;
	cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0;
	cred_r.ca_pk.ptr = NULL;

#endif
#ifdef MARCO
	uint8_t TEST_VEC_NUM = 1;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	c_i.sock = &sockfd;
	c_i.c_i.len = test_vectors[vec_num_i].c_i_len;
	c_i.c_i.ptr = (uint8_t *)test_vectors[vec_num_i].c_i;
	c_i.method = INITIATOR_SK_RESPONDER_SK;
	c_i.suites_i.len = sizeof(SUITES_I);
	c_i.suites_i.ptr = SUITES_I;
	c_i.ead_1.len = 0;
	c_i.ead_1.ptr = NULL;
	c_i.ead_3.len = 0;
	c_i.ead_3.ptr = NULL;
	/*ID_CRED_I*/
	c_i.id_cred_i.len = sizeof(ID_CRED_I);
	c_i.id_cred_i.ptr = ID_CRED_I;
	/*CRED_I*/
	c_i.cred_i.len = sizeof(CRED_I);
	c_i.cred_i.ptr = CRED_I;
	/*ephemeral key*/
	c_i.g_x.len = T1_RFC9529__G_X_LEN;
	c_i.g_x.ptr = (uint8_t *)T1_RFC9529__G_X;
	c_i.x.len = T1_RFC9529__X_LEN;
	c_i.x.ptr = (uint8_t *)T1_RFC9529__X;
	/*static key*/
	c_i.g_i.len = 0;
	c_i.g_i.ptr = NULL;
	c_i.i.len = 0;
	c_i.i.ptr = NULL;
	/**/
	c_i.sk_i.len = sizeof(SK_I);
	c_i.sk_i.ptr = SK_I;
	c_i.pk_i.len = sizeof(PK_I);
	c_i.pk_i.ptr = PK_I;

	cred_r.id_cred.len = 0;
	cred_r.id_cred.ptr = NULL;

	cred_r.cred.len = sizeof(CRED_R);
	cred_r.cred.ptr = CRED_R;

	cred_r.g.len = 0;
	cred_r.g.ptr = NULL;
	cred_r.pk.len = sizeof(PK_R);
	cred_r.pk.ptr = PK_R;
	cred_r.ca.len = 0;
	cred_r.ca.ptr = NULL;
	cred_r.ca_pk.len = 0;
	cred_r.ca_pk.ptr = NULL;

#endif

	struct cred_array cred_r_array = { .len = 1, .ptr = &cred_r };

#ifdef USE_RANDOM_EPHEMERAL_DH_KEY
	uint32_t seed;
	BYTE_ARRAY_NEW(X_random, 32, 32);
	BYTE_ARRAY_NEW(G_X_random, 32, 32);

	/*create a random seed*/
	FILE *fp;
	fp = fopen("/dev/urandom", "r");
	uint64_t seed_len = fread((uint8_t *)&seed, 1, sizeof(seed), fp);
	fclose(fp);
	PRINT_ARRAY("seed", (uint8_t *)&seed, seed_len);

	/*create ephemeral DH keys from seed*/
	TRY(ephemeral_dh_key_gen(P256, seed, &X_random, &G_X_random));
	c_i.g_x.ptr = G_X_random.ptr;
	c_i.g_x.len = G_X_random.len;
	c_i.x.ptr = X_random.ptr;
	c_i.x.len = X_random.len;
	PRINT_ARRAY("secret ephemeral DH key", c_i.g_x.ptr, c_i.g_x.len);
	PRINT_ARRAY("public ephemeral DH key", c_i.x.ptr, c_i.x.len);

#endif

#ifdef TINYCRYPT
	/* Register RNG function */
	uECC_set_rng(default_CSPRNG);
#endif

	TRY_EXPECT(start_coap_client(&sockfd), 0);
	TRY(edhoc_initiator_run(&c_i, &cred_r_array, &err_msg, &PRK_out, tx, rx,
				ead_process));

	PRINT_ARRAY("PRK_out", PRK_out.ptr, PRK_out.len);

	TRY(prk_out2exporter(SHA_256, &PRK_out, &prk_exporter));
	PRINT_ARRAY("prk_exporter", prk_exporter.ptr, prk_exporter.len);

	TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, &prk_exporter,
			   &oscore_master_secret));
	PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret.ptr,
		    oscore_master_secret.len);

	TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, &prk_exporter,
			   &oscore_master_salt));
	PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt.ptr,
		    oscore_master_salt.len);

	close(sockfd);
	return 0;
}
