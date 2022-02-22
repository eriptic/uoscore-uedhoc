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
#include "edhoc_test_vectors.h"
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

/**
 * @brief	Initializes socket for CoAP server.
 * @param	
 * @retval	error code
 */
static int start_coap_server(void)
{
	int err;
#ifdef USE_IPV4
	struct sockaddr_in servaddr;
	//struct sockaddr_in client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	const char IPV4_SERVADDR[] = { "127.0.0.1" };
	err = sock_init(SOCK_SERVER, IPV4_SERVADDR, IPv4, &servaddr,
			sizeof(servaddr));
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
			sizeof(servaddr));
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

enum err tx(void *sock, uint8_t *data, uint32_t data_len)
{
	txPDU->setCode(CoapPDU::COAP_CHANGED);
	txPDU->setPayload(data, data_len);
	send_coap_reply(sock, txPDU);
	return ok;
}

enum err rx(void *sock, uint8_t *data, uint32_t *data_len)
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
	if (*data_len >= payload_len) {
		memcpy(data, rxPDU->getPayloadPointer(), payload_len);
		*data_len = payload_len;
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
	uint8_t oscore_master_secret[16];
	uint8_t oscore_master_salt[8];

	/* edhoc declarations */
	uint8_t PRK_4x3m[PRK_DEFAULT_SIZE];
	uint8_t th4[SHA_DEFAULT_SIZE];
	uint8_t err_msg[ERR_MSG_DEFAULT_SIZE];
	uint32_t err_msg_len = sizeof(err_msg);
	uint8_t ad_1[AD_DEFAULT_SIZE];
	uint32_t ad_1_len = sizeof(ad_1);
	uint8_t ad_3[AD_DEFAULT_SIZE];
	uint32_t ad_3_len = sizeof(ad_1);

	/* test vector inputs */
	const uint8_t TEST_VEC_NUM = 1;
	uint16_t cred_num = 1;
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	TRY_EXPECT(start_coap_server(), 0);

	cred_i.id_cred.len = test_vectors[vec_num_i].id_cred_i_len;
	cred_i.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	cred_i.cred.len = test_vectors[vec_num_i].cred_i_len;
	cred_i.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	cred_i.g.len = test_vectors[vec_num_i].g_i_raw_len;
	cred_i.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	cred_i.pk.len = test_vectors[vec_num_i].pk_i_raw_len;
	cred_i.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;
	cred_i.ca.len = test_vectors[vec_num_i].ca_len;
	cred_i.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca;
	cred_i.ca_pk.len = test_vectors[vec_num_i].ca_pk_len;
	cred_i.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_pk;

	if (test_vectors[vec_num_i].c_r_raw != NULL) {
		c_r.c_r.type = BSTR;
		c_r.c_r.mem.c_x_bstr.len = test_vectors[vec_num_i].c_r_raw_len;
		c_r.c_r.mem.c_x_bstr.ptr =
			(uint8_t *)test_vectors[vec_num_i].c_r_raw;
	} else {
		c_r.c_r.type = INT;
		c_r.c_r.mem.c_x_int = *test_vectors[vec_num_i].c_r_raw_int;
	}
	c_r.msg4 = true; /*we allways test message 4 */
	c_r.suites_r.len = test_vectors[vec_num_i].suites_r_len;
	c_r.suites_r.ptr = (uint8_t *)test_vectors[vec_num_i].suites_r;
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
	c_r.sock = &sockfd;

	TRY(edhoc_responder_run(&c_r, &cred_i, cred_num, err_msg, &err_msg_len,
				(uint8_t *)&ad_1, &ad_1_len, (uint8_t *)&ad_3,
				&ad_3_len, PRK_4x3m, sizeof(PRK_4x3m), th4,
				sizeof(th4), tx, rx));
	PRINT_ARRAY("PRK_4x3m", PRK_4x3m, sizeof(PRK_4x3m));
	PRINT_ARRAY("th4", th4, sizeof(th4));

	TRY(edhoc_exporter(SHA_256, PRK_4x3m, sizeof(PRK_4x3m), th4,
			   sizeof(th4), "OSCORE_Master_Secret",
			   oscore_master_secret, 16));
	PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret, 16);

	TRY(edhoc_exporter(SHA_256, PRK_4x3m, sizeof(PRK_4x3m), th4,
			   sizeof(th4), "OSCORE_Master_Salt",
			   oscore_master_salt, 8));
	PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt, 8);

	/*
	 *  
	 * 
	 * Protected und unprotect communication over CoAP/OSCORE
	 * 
	 * 
	 */

	int err, n;
	char buffer[MAXLINE];
	struct context c_server;
	CoapPDU *recvPDU, *sendPDU = new CoapPDU();
	uint8_t coap_rx_buf[256];
	uint32_t coap_rx_buf_len = 0;
	uint8_t buf_oscore[256];
	uint32_t buf_oscore_len = sizeof(buf_oscore);
	bool oscore_flag;

	/*OSCORE contex initialization*/
	oscore_init_params params = {
		SERVER,
		sizeof(oscore_master_secret),
		oscore_master_secret,
		T1__RECIPIENT_ID_LEN,
		(uint8_t *)T1__RECIPIENT_ID,
		T1__SENDER_ID_LEN,
		(uint8_t *)T1__SENDER_ID,
		T1__ID_CONTEXT_LEN,
		(uint8_t *)T1__ID_CONTEXT,
		sizeof(oscore_master_salt),
		oscore_master_salt,
		OSCORE_AES_CCM_16_64_128,
		OSCORE_SHA_256,
	};
	TRY(oscore_context_init(&params, &c_server));

	while (1) {
		client_addr_len = sizeof(client_addr);
		memset(&client_addr, 0, sizeof(client_addr));

		n = recvfrom(sockfd, (char *)buffer, sizeof(buffer), 0,
			     (struct sockaddr *)&client_addr, &client_addr_len);
		if (n < 0) {
			return n;
		}

		TRY(oscore2coap((uint8_t *)buffer, n, coap_rx_buf,
				&coap_rx_buf_len, &oscore_flag, &c_server));

		if (oscore_flag) {
			/*we received an OSOCRE packet*/
			recvPDU = new CoapPDU((uint8_t *)coap_rx_buf,
					      coap_rx_buf_len);

			printf("\n=====================================================\n");
			printf("OSCORE packet received and converted to CoAP:\n");
			if (recvPDU->validate()) {
				recvPDU->printHuman();
			}

			prepare_CoAP_response(recvPDU, sendPDU);

			TRY(coap2oscore(sendPDU->getPDUPointer(),
					sendPDU->getPDULength(), buf_oscore,
					&buf_oscore_len, &c_server));

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
