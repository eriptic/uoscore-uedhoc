/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <stdio.h>

// #include <errno.h>
// #include <net/coap.h>
// #include <net/coap_link_format.h>
// #include <net/net_ip.h>
// //#include <net/net_mgmt.h>
// #include <net/socket.h>
// #include <net/udp.h>
// #include <sys/byteorder.h>
// #include <sys/printk.h>
// #include <zephyr.h>
// #include <zephyr/types.h>
//#include "net_private.h"

#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors.h"

#include <net/net_pkt.h>
#include <net/net_if.h>
#include <net/net_core.h>
#include <net/net_context.h>
#include <net/udp.h>
#include <net/coap.h>

#define MAX_COAP_MSG_LEN 256
#define BLOCK_WISE_TRANSFER_SIZE_GET 2048

/**
 * @brief	Initializes sockets for CoAP client.
 * @param
 * @retval	error code
 */
static int start_coap_client(int *sockfd)
{
	struct sockaddr_in6 servaddr;
	const char IPV6_SERVADDR[] = { "2001:db9::2" };
	int r = ipv6_sock_init(SOCK_CLIENT, IPV6_SERVADDR, &servaddr,
			       sizeof(servaddr), sockfd);
	if (r < 0) {
		printf("error during socket initialization (error code: %d)",
		       r);
		return -1;
	}
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
	/* Initialize the CoAP message */
	char *path = ".well-known/edhoc";
	struct coap_packet request;
	uint8_t _data[1000];

	TRY_EXPECT(coap_packet_init(&request, _data, sizeof(_data), 1,
				    COAP_TYPE_CON, 8, coap_next_token(),
				    COAP_METHOD_POST, coap_next_id()),
		   0);

	/* Append options */
	TRY_EXPECT(coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
					     path, strlen(path)),
		   0);

	/* Append Payload marker if you are going to add payload */
	TRY_EXPECT(coap_packet_append_payload_marker(&request), 0);

	/* Append payload */
	TRY_EXPECT(coap_packet_append_payload(&request, data, data_len), 0);

	send(*((int *)sock), request.data, request.offset, 0);

	/*construct a CoAP packet*/
	// static uint16_t mid = 0;
	// static uint32_t token = 0;
	// CoapPDU *pdu = new CoapPDU();
	// pdu->reset();
	// pdu->setVersion(1);
	// pdu->setType(CoapPDU::COAP_CONFIRMABLE);
	// pdu->setCode(CoapPDU::COAP_POST);
	// pdu->setToken((uint8_t *)&(++token), sizeof(token));
	// pdu->setMessageID(mid++);
	// pdu->setURI((char *)".well-known/edhoc", 17);
	// pdu->setPayload(data, data_len);

	// send(*((int *)sock), pdu->getPDUPointer(), pdu->getPDULength(), 0);

	// delete pdu;
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
	struct coap_packet reply;
	// CoapPDU *recvPDU;
	/* receive */
	n = recv(*((int *)sock), (char *)buffer, MAXLINE, MSG_WAITALL);
	if (n < 0) {
		printf("recv error");
	}

	TRY_EXPECT(coap_packet_parse(&reply, buffer, n, NULL, 0), 0);

	printf("coap header len %d\n", reply.hdr_len);

	// recvPDU = new CoapPDU((uint8_t *)buffer, n);

	// if (recvPDU->validate()) {
	// 	recvPDU->printHuman();
	// }

	// uint32_t payload_len = recvPDU->getPayloadLength();
	// printf("data_len: %d\n", *data_len);
	// printf("payload_len: %d\n", payload_len);

	// if (*data_len >= payload_len) {
	// 	memcpy(data, recvPDU->getPayloadPointer(), payload_len);
	// 	*data_len = payload_len;
	// } else {
	// 	printf("insufficient space in buffer");
	// 	return buffer_to_small;
	// }

	// delete recvPDU;
	return ok;
}

int main(void)
{
	uint8_t oscore_master_secret[16];
	uint8_t oscore_master_salt[8];

	/* edhoc declarations */
	uint8_t PRK_4x3m[PRK_DEFAULT_SIZE];
	uint8_t th4[SHA_DEFAULT_SIZE];
	uint8_t err_msg[ERR_MSG_DEFAULT_SIZE];
	uint32_t err_msg_len = sizeof(err_msg);
	uint8_t ad_2[AD_DEFAULT_SIZE];
	uint32_t ad_2_len = sizeof(ad_2);
	uint8_t ad_4[AD_DEFAULT_SIZE];
	uint32_t ad_4_len = sizeof(ad_2);

	/* test vector inputs */
	const uint8_t TEST_VEC_NUM = 1;
	uint16_t cred_num = 1;
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;

	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	if (test_vectors[vec_num_i].c_i_raw != NULL) {
		c_i.c_i.type = BSTR;
		c_i.c_i.mem.c_x_bstr.len = test_vectors[vec_num_i].c_i_raw_len;
		c_i.c_i.mem.c_x_bstr.ptr =
			(uint8_t *)test_vectors[vec_num_i].c_i_raw;
	} else {
		c_i.c_i.type = INT;
		c_i.c_i.mem.c_x_int = *test_vectors[vec_num_i].c_i_raw_int;
	}
	c_i.msg4 = true;
	c_i.method = (enum method_type) * test_vectors[vec_num_i].method;
	c_i.suites_i.len = test_vectors[vec_num_i].suites_i_len;
	c_i.suites_i.ptr = (uint8_t *)test_vectors[vec_num_i].suites_i;
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
	cred_r.ca.len = test_vectors[vec_num_i].ca_len;
	cred_r.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca;
	cred_r.ca_pk.len = test_vectors[vec_num_i].ca_pk_len;
	cred_r.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_pk;

	c_i.sock = NULL;
	TRY_EXPECT(start_coap_client((int *)c_i.sock), 0);

	TRY(edhoc_initiator_run(&c_i, &cred_r, cred_num, err_msg, &err_msg_len,
				ad_2, &ad_2_len, ad_4, &ad_4_len, PRK_4x3m,
				sizeof(PRK_4x3m), th4, sizeof(th4), tx, rx));

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

	close(*(int *)c_i.sock);
	return 0;
}
