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

struct context c_client;

int main()
{
	setbuf(stdout, NULL); //disable printf buffereing
	err r;
	int err;
	char buffer[MAXLINE];

#ifdef USE_IPV4
	struct sockaddr_in servaddr;
	const char IPV4_SERVADDR[] = { "127.0.0.1" };
	err = sock_init(SOCK_CLIENT, IPV4_SERVADDR, IPv4, &servaddr,
			sizeof(servaddr));
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
			sizeof(servaddr));
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif

	/*construct a CoAP packet*/
	uint16_t mid1 = 256, mid2 = 0;
	uint32_t token = 0;
	int32_t n;
	uint32_t len;
	bool oscore_flag = false;
	CoapPDU *unprotected_pdu = new CoapPDU();
	CoapPDU *protected_pdu = new CoapPDU();

	/*OSCORE contex initialization*/
	oscore_init_params params = {
		CLIENT,
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
	};
	r = oscore_context_init(&params, &c_client);

	if (r != ok) {
		printf("Error during establishing an OSCORE security context!\n");
	}

	uint8_t buf_oscore[256];
	uint32_t buf_oscore_len = sizeof(buf_oscore);
	uint8_t coap_rx_buf[256];
	uint32_t coap_rx_buf_len = 0;
	CoapPDU *recvPDU;
	bool request_secure_resource = true;
	uint8_t request_payload[] = { "This is some payload" };

	while (1) {
		if (request_secure_resource) {
			/* send OSCORE request*/
			request_secure_resource = false;
			protected_pdu->reset();
			protected_pdu->setVersion(1);
			protected_pdu->setType(CoapPDU::COAP_CONFIRMABLE);
			protected_pdu->setCode(CoapPDU::COAP_GET);
			protected_pdu->setToken((uint8_t *)&(++token),
						sizeof(token));
			protected_pdu->setURI((char *)"tv1", 3);
			protected_pdu->setMessageID(mid1++);
			protected_pdu->setPayload(request_payload,
						  sizeof(request_payload));

			if (protected_pdu->validate()) {
				printf("\n=================================================\n");
				printf("CoAP message to be protected with OSOCRE\n");
				protected_pdu->printHuman();
			}

			r = coap2oscore(protected_pdu->getPDUPointer(),
					(uint16_t)protected_pdu->getPDULength(),
					buf_oscore, &buf_oscore_len, &c_client);
			if (r != ok) {
				printf("Error in coap2oscore (Error code %d)!\n",
				       r);
			}

			sendto(sockfd, buf_oscore, buf_oscore_len, 0,
			       (const struct sockaddr *)&servaddr,
			       sizeof(servaddr));

			/* receive */
			n = recvfrom(sockfd, (char *)buffer, MAXLINE,
				     MSG_WAITALL, (struct sockaddr *)&servaddr,
				     &len);
			if (n < 0) {
				printf("no response received\n");
			} else {
				r = oscore2coap((uint8_t *)buffer, n,
						coap_rx_buf, &coap_rx_buf_len,
						&oscore_flag, &c_client);

				if (r != ok) {
					printf("Error in oscore2coap (Error code %d)!\n",
					       r);
				}
				recvPDU = new CoapPDU((uint8_t *)coap_rx_buf,
						      coap_rx_buf_len);
				if (recvPDU->validate()) {
					printf("\n===================================================\n");
					printf("Response CoAP message\n");
					recvPDU->printHuman();
				}
			}

		} else {
			/* send CoAP request*/
			request_secure_resource = true;
			unprotected_pdu->reset();
			unprotected_pdu->setVersion(1);
			unprotected_pdu->setType(CoapPDU::COAP_CONFIRMABLE);
			unprotected_pdu->setCode(CoapPDU::COAP_GET);
			unprotected_pdu->setToken((uint8_t *)&(++token),
						  sizeof(token));
			unprotected_pdu->setURI((char *)"tv2", 3);
			unprotected_pdu->setMessageID(mid2++);
			unprotected_pdu->setPayload(request_payload,
						    sizeof(request_payload));

			if (unprotected_pdu->validate()) {
				printf("\n=================================================\n");
				printf("Unprotected CoAP message\n");
				unprotected_pdu->printHuman();
			}

			sendto(sockfd, unprotected_pdu->getPDUPointer(),
			       unprotected_pdu->getPDULength(), 0,
			       (const struct sockaddr *)&servaddr,
			       sizeof(servaddr));

			/* receive */
			n = recvfrom(sockfd, (char *)buffer, MAXLINE,
				     MSG_WAITALL, (struct sockaddr *)&servaddr,
				     &len);

			if (n < 0) {
				printf("no response received\n");
			} else {
				recvPDU = new CoapPDU((uint8_t *)buffer, n);
				if (recvPDU->validate()) {
					printf("\n=============================================\n");
					printf("Response CoAP message\n");
					recvPDU->printHuman();
				}
			}
		}
		/*wait 5 sec before sending the next packet*/
		sleep(5);
	}
	close(sockfd);
	return 0;
}
