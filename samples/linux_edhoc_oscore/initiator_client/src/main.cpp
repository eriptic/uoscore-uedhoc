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
#include "oscore.h"
#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"
#include "oscore_test_vectors.h"
}
#include "cantcoap.h"

#define USE_IPV4
#define ECHO_OPT_NUM 252

struct context c_client;

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
	const char IPV4_SERVADDR[] = { "127.0.0.1" };
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
	const char IPV6_SERVADDR[] = { "::1" };
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

/**
 * @brief	Callback function called inside the frontend when data needs to 
 * 		be send over the network. We use here CoAP as transport 
 * @param	data pointer to the data that needs to be send
 * @param	data_len lenhgt of the data in bytes
 */
enum err tx(void *sock, uint8_t *data, uint32_t data_len)
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
	pdu->setPayload(data, data_len);

	send(*(int *)sock, pdu->getPDUPointer(), pdu->getPDULength(), 0);

	delete pdu;
	return ok;
}

/**
 * @brief	Callback function called inside the frontend when data needs to 
 * 		be received over the network. We use here CoAP as transport 
 * @param	data pointer to the data that needs to be received
 * @param	data_len lenhgt of the data in bytes
 */
enum err rx(void *sock, uint8_t *data, uint32_t *data_len)
{
	int n;
	char buffer[MAXLINE];
	CoapPDU *recvPDU;
	/* receive */
	n = recv(*(int *)sock, (char *)buffer, MAXLINE, MSG_WAITALL);
	if (n < 0) {
		printf("recv error");
	}

	recvPDU = new CoapPDU((uint8_t *)buffer, n);

	if (recvPDU->validate()) {
		recvPDU->printHuman();
	}

	uint32_t payload_len = recvPDU->getPayloadLength();
	printf("data_len: %d\n", *data_len);
	printf("payload_len: %d\n", payload_len);

	if (*data_len >= payload_len) {
		memcpy(data, recvPDU->getPayloadPointer(), payload_len);
		*data_len = payload_len;
	} else {
		printf("insufficient space in buffer");
		return buffer_to_small;
	}

	delete recvPDU;
	return ok;
}

int main()
{
	/*
	 *  
	 * 
	 * Derive Master secret for OSCORE by using EDHOC.
	 * 
	 * 
	 */
	int sockfd;
	uint8_t oscore_master_secret[16];
	uint8_t oscore_master_salt[8];

	/* edhoc declarations */
	uint8_t PRK_out[PRK_DEFAULT_SIZE];
	uint8_t prk_exporter[32];
	uint8_t err_msg[ERR_MSG_DEFAULT_SIZE];
	uint32_t err_msg_len = sizeof(err_msg);

	/* test vector inputs */
	const uint8_t TEST_VEC_NUM = 1;
	uint16_t cred_num = 1;
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	TRY_EXPECT(start_coap_client(&sockfd), 0);

	c_i.c_i.len = test_vectors[vec_num_i].c_i_len;
	c_i.c_i.ptr = (uint8_t *)test_vectors[vec_num_i].c_i;
	c_i.msg4 = true;
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
	c_i.sock = &sockfd;

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

#ifdef TINYCRYPT
		/* Register RNG function */
		uECC_set_rng(default_CSPRNG);
#endif

	TRY(edhoc_initiator_run(&c_i, &cred_r, cred_num, err_msg, &err_msg_len,
				NULL, NULL, NULL, NULL, PRK_out,
				sizeof(PRK_out), tx, rx));

	PRINT_ARRAY("PRK_out", PRK_out, sizeof(PRK_out));

	TRY(prk_out2exporter(SHA_256, PRK_out, sizeof(PRK_out), prk_exporter));
	PRINT_ARRAY("prk_exporter", prk_exporter, sizeof(prk_exporter));

	TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, prk_exporter,
			   sizeof(prk_exporter), oscore_master_secret,
			   sizeof(oscore_master_secret)));
	PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret,
		    sizeof(oscore_master_secret));

	TRY(edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, prk_exporter,
			   sizeof(prk_exporter), oscore_master_salt,
			   sizeof(oscore_master_salt)));
	PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt,
		    sizeof(oscore_master_salt));

	/*
	 *  
	 * 
	 * Protected und unprotect communication over CoAP/OSCORE
	 * 
	 * 
	 */
	char buffer[MAXLINE];

	/*construct a CoAP packet*/
	uint16_t mid1 = 256;
	uint32_t token = 0;
	int32_t n;
	CoapPDU *protected_pdu = new CoapPDU();

	/*OSCORE contex initialization*/
	oscore_init_params params = {
		sizeof(oscore_master_secret),
		oscore_master_secret,
		T1__SENDER_ID_LEN,
		(uint8_t *)T1__SENDER_ID,
		T1__RECIPIENT_ID_LEN,
		(uint8_t *)T1__RECIPIENT_ID,
		T1__ID_CONTEXT_LEN,
		(uint8_t *)T1__ID_CONTEXT,
		sizeof(oscore_master_salt),
		oscore_master_salt,
		OSCORE_AES_CCM_16_64_128,
		OSCORE_SHA_256,
		true,
	};
	TRY(oscore_context_init(&params, &c_client));

	uint8_t buf_oscore[256];
	uint8_t coap_rx_buf[256];
	CoapPDU *recvPDU;
	uint8_t request_payload[] = { "This is some payload" };
	bool first_response = true;
	bool second_request = false;
	uint8_t echo_opt_val[12];

	while (1) {
		uint32_t buf_oscore_len = sizeof(buf_oscore);
		uint32_t coap_rx_buf_len = sizeof(coap_rx_buf);

		/* send OSCORE request*/
		protected_pdu->reset();
		protected_pdu->setVersion(1);
		protected_pdu->setType(CoapPDU::COAP_CONFIRMABLE);
		protected_pdu->setCode(CoapPDU::COAP_GET);
		protected_pdu->setToken((uint8_t *)&(++token), sizeof(token));
		protected_pdu->setURI((char *)"tv1", 3);
		protected_pdu->setMessageID(mid1++);
		if (second_request) {
			protected_pdu->addOption(ECHO_OPT_NUM,
						 sizeof(echo_opt_val),
						 echo_opt_val);
			second_request = false;
		}
		protected_pdu->setPayload(request_payload,
					  sizeof(request_payload));

		if (protected_pdu->validate()) {
			printf("\n=================================================\n");
			printf("CoAP message to be protected with OSOCRE\n");
			protected_pdu->printHuman();
		}

		enum err r =
			coap2oscore(protected_pdu->getPDUPointer(),
				    (uint16_t)protected_pdu->getPDULength(),
				    buf_oscore, &buf_oscore_len, &c_client);
		if (r != ok) {
			printf("Error in coap2oscore (Error code %d)!\n", r);
		}

		send(sockfd, buf_oscore, buf_oscore_len, 0);

		/* receive */
		n = recv(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL);
		if (n < 0) {
			printf("no response received\n");
		} else {
			r = oscore2coap((uint8_t *)buffer, n, coap_rx_buf,
					&coap_rx_buf_len, &c_client);

			if (r != ok) {
				printf("Error in oscore2coap (Error code %d)!\n",
				       r);
			}
			recvPDU = new CoapPDU((uint8_t *)coap_rx_buf,
					      coap_rx_buf_len);
			if (recvPDU->validate()) {
				printf("\n=============================================\n");
				printf("Response CoAP message\n");
				recvPDU->printHuman();
			}

			if (first_response) {
				first_response = false;
				CoapPDU::CoapOption *opts =
					recvPDU->getOptions();
				int num_opts = recvPDU->getNumOptions();
				for (int i = 0; i < num_opts; i++) {
					if (opts[i].optionNumber ==
					    ECHO_OPT_NUM) {
						printf("A response to the first request is received, which contains an ECHO option\n");
						memcpy(echo_opt_val,
						       opts[i].optionValuePointer,
						       opts[i].optionValueLength);
						second_request = true;
						break;
					}
				}
			}
		}

		/*wait 5 sec before sending the next packet*/
		sleep(5);
	}
	close(sockfd);
	return 0;
}
