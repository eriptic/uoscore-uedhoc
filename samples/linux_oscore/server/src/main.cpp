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

static void prepare_first_CoAP_response(CoapPDU *recvPDU, CoapPDU *sendPDU)
{
	/*This is just an example of an ECHO value. In production deployments the ECHO value MUST be computes as stated in Appendix A.2 or A.3 RFC9175*/
	uint8_t echo_opt_val[] = { 0x00, 0x01, 0x02, 0x03, 0x04, 0x05,
				   0x06, 0x07, 0x08, 0x09, 0x10, 0x11 };

	sendPDU->reset();
	sendPDU->setVersion(1);
	sendPDU->setType(CoapPDU::COAP_ACKNOWLEDGEMENT);
	sendPDU->setCode(CoapPDU::COAP_UNAUTHORIZED);
	sendPDU->setToken(recvPDU->getTokenPointer(),
			  recvPDU->getTokenLength());
	sendPDU->setMessageID(recvPDU->getMessageID());
	sendPDU->addOption(ECHO_OPT_NUM, sizeof(echo_opt_val), echo_opt_val);
	sendPDU->setPayload(NULL, 0);

	printf("\n=============================================================\n");
	printf("Unprotected first response:\n");
	if (sendPDU->validate()) {
		sendPDU->printHuman();
	}
}

static void prepare_CoAP_response(CoapPDU *recvPDU, CoapPDU *sendPDU)
{
	uint8_t response_msg[] = { "This is a response!" };
	sendPDU->reset();
	sendPDU->setVersion(1);
	sendPDU->setType(CoapPDU::COAP_ACKNOWLEDGEMENT);
	sendPDU->setCode(CoapPDU::COAP_CONTENT);
	sendPDU->setToken(recvPDU->getTokenPointer(),
			  recvPDU->getTokenLength());
	sendPDU->setMessageID(recvPDU->getMessageID());
	sendPDU->setPayload(response_msg, sizeof(response_msg));

	printf("\n=============================================================\n");
	printf("Unprotected response:\n");
	if (sendPDU->validate()) {
		sendPDU->printHuman();
	}
}

int main()
{
	setbuf(stdout, NULL); //disable printf buffereing
	err r;
	int err, n;
	char buffer[MAXLINE];
	socklen_t client_addr_len;
	struct context c_server;
	CoapPDU *recvPDU, *sendPDU = new CoapPDU();
	uint8_t coap_rx_buf[256];
	uint32_t coap_rx_buf_len = 0;
	uint8_t buf_oscore[256];
	int sockfd;

#ifdef USE_IPV4
	struct sockaddr_in servaddr;
	struct sockaddr_in client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	const char IPV4_SERVADDR[] = { "127.0.0.1" };
	err = sock_init(SOCK_SERVER, IPV4_SERVADDR, IPv4, &servaddr,
			sizeof(servaddr), &sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif
#ifdef USE_IPV6
	struct sockaddr_in6 servaddr;
	struct sockaddr_in6 client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	const char IPV6_SERVADDR[] = { "::1" };
	err = sock_init(SOCK_SERVER, IPV6_SERVADDR, IPv6, &servaddr,
			sizeof(servaddr), &sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif

	/*OSCORE context initialization*/
	oscore_init_params params = {
		T1__MASTER_SECRET_LEN,
		(uint8_t *)T1__MASTER_SECRET,
		T1__RECIPIENT_ID_LEN,
		(uint8_t *)T1__RECIPIENT_ID,
		T1__SENDER_ID_LEN,
		(uint8_t *)T1__SENDER_ID,
		T1__ID_CONTEXT_LEN,
		(uint8_t *)T1__ID_CONTEXT,
		T1__MASTER_SALT_LEN,
		(uint8_t *)T1__MASTER_SALT,
		OSCORE_AES_CCM_16_64_128,
		OSCORE_SHA_256,
		true,
	};
	r = oscore_context_init(&params, &c_server);
	if (r != ok) {
		printf("Error during establishing an OSCORE security context!\n");
	}

	while (1) {
		uint32_t buf_oscore_len = sizeof(buf_oscore);
		n = recvfrom(sockfd, (char *)buffer, sizeof(buffer), 0,
			     (struct sockaddr *)&client_addr, &client_addr_len);
		if (n < 0)
			return n;

		r = oscore2coap((uint8_t *)buffer, n, coap_rx_buf,
				&coap_rx_buf_len, &c_server);

		if (r != ok && r != not_oscore_pkt &&
		    r != first_request_after_reboot) {
			printf("Error in oscore2coap (error code %d)!\n", r);
		}

		if (r != not_oscore_pkt) {
			/*we received an OSCORE packet*/

			printf("\n=====================================================\n");

			if (r == first_request_after_reboot) {
				/*we are here when the server received a first request after reboot*/
				/*we assume that the server has rebooted before calling oscore_context_init*/
				recvPDU = new CoapPDU((uint8_t *)buffer, n);
				printf("First OSCORE packet received after reboot:\n");
				if (recvPDU->validate()) {
					recvPDU->printHuman();
				}
				prepare_first_CoAP_response(recvPDU, sendPDU);
			} else {
				recvPDU = new CoapPDU((uint8_t *)coap_rx_buf,
						      coap_rx_buf_len);
				printf("OSCORE packet received and converted to CoAP:\n");
				if (recvPDU->validate()) {
					recvPDU->printHuman();
				}
				prepare_CoAP_response(recvPDU, sendPDU);
			}

			r = coap2oscore(sendPDU->getPDUPointer(),
					sendPDU->getPDULength(), buf_oscore,
					&buf_oscore_len, &c_server);
			if (r != ok) {
				printf("Error in coap2oscore (error code %d)!\n",
				       r);
			}

			err = sendto(sockfd, buf_oscore, buf_oscore_len, 0,
				     (struct sockaddr *)&client_addr,
				     client_addr_len);
			if (err < 0)
				return err;

		} else {
			/*we received a CoAP packet*/
			recvPDU = new CoapPDU((uint8_t *)buffer, n);
			printf("\n=====================================================\n");
			printf("Unprotected CoAP packet received:\n");
			if (recvPDU->validate()) {
				recvPDU->printHuman();
			}

			prepare_CoAP_response(recvPDU, sendPDU);

			err = sendto(sockfd, sendPDU->getPDUPointer(),
				     sendPDU->getPDULength(), 0,
				     (struct sockaddr *)&client_addr,
				     client_addr_len);
			if (err < 0) {
				return err;
			}
		}
	}

	return 0;
}
