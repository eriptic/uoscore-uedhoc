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
#include "sock.h"
}
#include "cantcoap.h"
#include "oscore_test_vectors.h"

#define USE_IPV6
#define ECHO_OPT_NUM 252

struct context c_client;

int main()
{
	setbuf(stdout, NULL); //disable printf buffereing
	err r;
	int err;
	char buffer[MAXLINE];
	int sockfd;

#ifdef USE_IPV4
	struct sockaddr_in servaddr;
	const char IPV4_SERVADDR[] = { "127.0.0.1" };
	err = sock_init(SOCK_CLIENT, IPV4_SERVADDR, IPv4, &servaddr,
			sizeof(servaddr), &sockfd);
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
			sizeof(servaddr), &sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif

	/*construct a CoAP packet*/
	uint16_t mid1 = 256;
	uint32_t token = 0;
	int32_t n;
	uint32_t len;
	bool first_response = true;
	bool second_request = false;
	CoapPDU *protected_pdu = new CoapPDU();

	/*OSCORE context initialization*/
	oscore_init_params params = {
		T1__MASTER_SECRET_LEN,
		(uint8_t *)T1__MASTER_SECRET,
		T1__SENDER_ID_LEN,
		(uint8_t *)T1__SENDER_ID,
		T1__RECIPIENT_ID_LEN,
		(uint8_t *)T1__RECIPIENT_ID,
		T1__ID_CONTEXT_LEN,
		(uint8_t *)T1__ID_CONTEXT,
		T1__MASTER_SALT_LEN,
		(uint8_t *)T1__MASTER_SALT,
		OSCORE_AES_CCM_16_64_128,
		OSCORE_SHA_256,
		true,
	};
	r = oscore_context_init(&params, &c_client);

	if (r != ok) {
		printf("Error during establishing an OSCORE security context!\n");
	}

	uint8_t buf_oscore[256];
	uint8_t coap_rx_buf[256];
	CoapPDU *recvPDU;
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

		if (protected_pdu->validate()) {
			printf("\n=================================================\n");
			printf("CoAP message to be protected with OSOCRE\n");
			protected_pdu->printHuman();
		}

		r = coap2oscore(protected_pdu->getPDUPointer(),
				(uint16_t)protected_pdu->getPDULength(),
				buf_oscore, &buf_oscore_len, &c_client);
		if (r != ok) {
			printf("Error in coap2oscore (Error code %d)!\n", r);
		}

		sendto(sockfd, buf_oscore, buf_oscore_len, 0,
		       (const struct sockaddr *)&servaddr, sizeof(servaddr));

		/* receive */
		n = recvfrom(sockfd, (char *)buffer, MAXLINE, MSG_WAITALL,
			     (struct sockaddr *)&servaddr, &len);
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
