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
#include <errno.h>

extern "C" {
#include "oscore.h"
#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"
#include "oscore_test_vectors.h"
}
#include "cantcoap.h"

#define USE_IPV4

CoapPDU *txPDU = new CoapPDU();

char buffer[MAXLINE];
CoapPDU *rxPDU;

#ifdef USE_IPV6
struct sockaddr_in6 client_addr;
#endif
#ifdef USE_IPV4
struct sockaddr_in client_addr;
#endif
socklen_t client_addr_len;

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

/**
 * @brief	Initializes socket for CoAP server.
 * @param	
 * @retval	error code
 */
static int start_coap_server(int *sockfd)
{
	int err;
#ifdef USE_IPV4
	struct sockaddr_in servaddr;
	//struct sockaddr_in client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	const char IPV4_SERVADDR[] = { "127.0.0.1" };
	err = sock_init(SOCK_SERVER, IPV4_SERVADDR, IPv4, &servaddr,
			sizeof(servaddr), sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}
#endif
#ifdef USE_IPV6
	struct sockaddr_in6 servaddr;
	//struct sockaddr_in6 client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	const char IPV6_SERVADDR[] = { "::1" };
	err = sock_init(SOCK_SERVER, IPV6_SERVADDR, IPv6, &servaddr,
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
 * @brief	Sends CoAP packet over network.
 * @param	pdu pointer to CoAP packet
 * @retval	error code
 */
static int send_coap_reply(void *sock, CoapPDU *pdu)
{
	int r;

	r = sendto(*(int *)sock, pdu->getPDUPointer(), pdu->getPDULength(), 0,
		   (struct sockaddr *)&client_addr, client_addr_len);
	if (r < 0) {
		printf("Error: failed to send reply (Code: %d, ErrNo: %d)\n", r,
		       errno);
		return r;
	}

	//printf("CoAP reply sent!\n");
	return 0;
}

enum err ead_process(void *params, struct byte_array *ead13)
{
	/*for this sample we are not using EAD*/
	/*to save RAM we use FEATURES += -DEAD_SIZE=0*/
	return ok;
}

enum err tx(void *sock, struct byte_array *data)
{
	txPDU->setCode(CoapPDU::COAP_CHANGED);
	txPDU->setPayload(data->ptr, data->len);
	send_coap_reply(sock, txPDU);
	return ok;
}

enum err rx(void *sock, struct byte_array *data)
{
	int n;

	/* receive */
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));

	n = recvfrom(*(int *)sock, (char *)buffer, sizeof(buffer), 0,
		     (struct sockaddr *)&client_addr, &client_addr_len);
	if (n < 0) {
		printf("recv error");
	}

	rxPDU = new CoapPDU((uint8_t *)buffer, n);

	if (rxPDU->validate()) {
		rxPDU->printHuman();
	}

	// PRINT_ARRAY("CoAP message", rxPDU->getPayloadPointer(),
	// 	    rxPDU->getPayloadLength());

	uint32_t payload_len = rxPDU->getPayloadLength();
	if (data->len >= payload_len) {
		memcpy(data->ptr, rxPDU->getPayloadPointer(), payload_len);
		data->len = payload_len;
	} else {
		printf("insufficient space in buffer");
	}

	txPDU->reset();
	txPDU->setVersion(rxPDU->getVersion());
	txPDU->setMessageID(rxPDU->getMessageID());
	txPDU->setToken(rxPDU->getTokenPointer(), rxPDU->getTokenLength());

	if (rxPDU->getType() == CoapPDU::COAP_CONFIRMABLE) {
		txPDU->setType(CoapPDU::COAP_ACKNOWLEDGEMENT);
	} else {
		txPDU->setType(CoapPDU::COAP_NON_CONFIRMABLE);
	}

	delete rxPDU;
	return ok;
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
	/*
	 *  
	 * 
	 * Derive Master secret for OSCORE by using EDHOC.
	 * 
	 * 
	 */
	int sockfd;
	BYTE_ARRAY_NEW(prk_exporter, 32, 32);
	BYTE_ARRAY_NEW(oscore_master_secret, 16, 16);
	BYTE_ARRAY_NEW(oscore_master_salt, 8, 8);
	BYTE_ARRAY_NEW(PRK_out, 32, 32);
	BYTE_ARRAY_NEW(err_msg, 0, 0);

	/* test vector inputs */
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	const uint8_t TEST_VEC_NUM = 1;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	TRY_EXPECT(start_coap_server(&sockfd), 0);

	c_r.sock = &sockfd;
	c_r.c_r.ptr = (uint8_t *)test_vectors[vec_num_i].c_r;
	c_r.c_r.len = test_vectors[vec_num_i].c_r_len;
	c_r.suites_r.len = test_vectors[vec_num_i].SUITES_R_len;
	c_r.suites_r.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_R;
	c_r.ead_2.len = test_vectors[vec_num_i].ead_2_len;
	c_r.ead_2.ptr = (uint8_t *)test_vectors[vec_num_i].ead_2;
	c_r.ead_4.len = test_vectors[vec_num_i].ead_4_len;
	c_r.ead_4.ptr = (uint8_t *)test_vectors[vec_num_i].ead_4;
	c_r.id_cred_r.len = test_vectors[vec_num_i].id_cred_r_len;
	c_r.id_cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_r;
	c_r.cred_r.len = test_vectors[vec_num_i].cred_r_len;
	c_r.cred_r.ptr = (uint8_t *)test_vectors[vec_num_i].cred_r;
	c_r.g_y.len = test_vectors[vec_num_i].g_y_raw_len;
	c_r.g_y.ptr = (uint8_t *)test_vectors[vec_num_i].g_y_raw;
	c_r.y.len = test_vectors[vec_num_i].y_raw_len;
	c_r.y.ptr = (uint8_t *)test_vectors[vec_num_i].y_raw;
	c_r.g_r.len = test_vectors[vec_num_i].g_r_raw_len;
	c_r.g_r.ptr = (uint8_t *)test_vectors[vec_num_i].g_r_raw;
	c_r.r.len = test_vectors[vec_num_i].r_raw_len;
	c_r.r.ptr = (uint8_t *)test_vectors[vec_num_i].r_raw;
	c_r.sk_r.len = test_vectors[vec_num_i].sk_r_raw_len;
	c_r.sk_r.ptr = (uint8_t *)test_vectors[vec_num_i].sk_r_raw;
	c_r.pk_r.len = test_vectors[vec_num_i].pk_r_raw_len;
	c_r.pk_r.ptr = (uint8_t *)test_vectors[vec_num_i].pk_r_raw;

	cred_i.id_cred.len = test_vectors[vec_num_i].id_cred_i_len;
	cred_i.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	cred_i.cred.len = test_vectors[vec_num_i].cred_i_len;
	cred_i.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	cred_i.g.len = test_vectors[vec_num_i].g_i_raw_len;
	cred_i.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	cred_i.pk.len = test_vectors[vec_num_i].pk_i_raw_len;
	cred_i.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;
	cred_i.ca.len = test_vectors[vec_num_i].ca_i_len;
	cred_i.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i;
	cred_i.ca_pk.len = test_vectors[vec_num_i].ca_i_pk_len;
	cred_i.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i_pk;

	struct cred_array cred_i_array = { .len = 1, .ptr = &cred_i };

#ifdef TINYCRYPT
	/* Register RNG function */
	uECC_set_rng(default_CSPRNG);
#endif

	TRY(edhoc_responder_run(&c_r, &cred_i_array, &err_msg, &PRK_out, tx, rx,
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

	/*
	 *  
	 * 
	 * Protected und unprotected communication over CoAP/OSCORE
	 * 
	 * 
	 */

	int err, n;
	char buffer[MAXLINE];
	struct context c_server;
	CoapPDU *recvPDU, *sendPDU = new CoapPDU();
	uint8_t coap_rx_buf[256];
	uint8_t buf_oscore[256];

	/*OSCORE contex initialization*/
	oscore_init_params params = {
		oscore_master_secret.len,
		oscore_master_secret.ptr,
		T1__RECIPIENT_ID_LEN,
		(uint8_t *)T1__RECIPIENT_ID,
		T1__SENDER_ID_LEN,
		(uint8_t *)T1__SENDER_ID,
		T1__ID_CONTEXT_LEN,
		(uint8_t *)T1__ID_CONTEXT,
		oscore_master_salt.len,
		oscore_master_salt.ptr,
		OSCORE_AES_CCM_16_64_128,
		OSCORE_SHA_256,
		true,
	};
	TRY(oscore_context_init(&params, &c_server));

	while (1) {
		uint32_t buf_oscore_len = sizeof(buf_oscore);
		uint32_t coap_rx_buf_len = sizeof(coap_rx_buf);
		client_addr_len = sizeof(client_addr);
		memset(&client_addr, 0, sizeof(client_addr));

		n = recvfrom(sockfd, (char *)buffer, sizeof(buffer), 0,
			     (struct sockaddr *)&client_addr, &client_addr_len);
		if (n < 0) {
			return n;
		}

		enum err r = oscore2coap((uint8_t *)buffer, n, coap_rx_buf,
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
			if (err < 0)
				return err;
		}
	}

	return 0;
}
