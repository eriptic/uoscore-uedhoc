/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <logging/log.h>
#include <stdio.h>
LOG_MODULE_REGISTER(net_coap_client_sample, LOG_LEVEL_DBG);

#include <edhoc.h>
#include <errno.h>
#include <net/coap.h>
#include <net/coap_link_format.h>
#include <net/net_ip.h>
#include <net/net_mgmt.h>
#include <net/socket.h>
#include <net/udp.h>
#include <sys/byteorder.h>
#include <sys/printk.h>
#include <zephyr.h>
#include <zephyr/types.h>

#include "net_private.h"

#define MAX_COAP_MSG_LEN 256

#define PEER_PORT 5683

#define BLOCK_WISE_TRANSFER_SIZE_GET 2048

/* Uncomment the following line to enable printf output */
#define ENABLE_PRINTK
#ifdef ENABLE_PRINTK
#define PRINTK(text, ...) printk(text, ##__VA_ARGS__)
#else
#define PRINTK(text, ...)
#endif

/* Create queues for EDHOC */
#define MBOX_MSG_SIZE 300
#define MBOX_WAIT_TIME 20
K_MBOX_DEFINE(rx_queue);
K_MBOX_DEFINE(tx_queue);

enum dev_type { SERVER, CLIENT };

#define VEC_NUM 1

/**
 * @brief	Callback function called inside the frontend when data needs to 
 * 		be send over the network. We use here CoAP as transport 
 * @param	data pointer to the data that needs to be send
 * @param	data_len lenhgt of the data in bytes
 */
enum err tx(void *sock, uint8_t *data, uint32_t data_len)
{
	// /*construct a CoAP packet*/
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
	// int n;
	// char buffer[MAXLINE];
	// CoapPDU *recvPDU;
	// /* receive */
	// n = recv(*((int *)sock), (char *)buffer, MAXLINE, MSG_WAITALL);
	// if (n < 0) {
	// 	printf("recv error");
	// }

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

/**
 * @brief	Entry function of EDHOC thread. Starts EDHOC initiator.
 * @param
 * @retval	none
 */
void edhoc_initiator_init(void)
{
	uint8_t vec_num = VEC_NUM - 1;

	uint8_t PRK_4x3m[PRK_DEFAULT_SIZE];
	uint8_t th4[SHA_DEFAULT_SIZE];
	uint8_t err_msg[ERR_MSG_DEFAULT_SIZE];
	uint32_t err_msg_len = sizeof(err_msg);
	uint8_t ad_1[AD_DEFAULT_SIZE];
	uint32_t ad_1_len = sizeof(ad_1);
	uint8_t ad_2[AD_DEFAULT_SIZE];
	uint32_t ad_2_len = sizeof(ad_2);
	uint8_t ad_3[AD_DEFAULT_SIZE];
	uint32_t ad_3_len = sizeof(ad_3);
	uint8_t ad_4[AD_DEFAULT_SIZE];
	uint32_t ad_4_len = sizeof(ad_2);
	uint16_t cred_num = 1;
	struct other_party_cred cred_r;
	struct edhoc_initiator_context c_i;
	enum err err;

	rx_initiator_switch = true;
	cred_r.id_cred.len = test_vectors[vec_num].id_cred_r_len;
	cred_r.id_cred.ptr = (uint8_t *)test_vectors[vec_num].id_cred_r;
	cred_r.cred.len = test_vectors[vec_num].cred_r_len;
	cred_r.cred.ptr = (uint8_t *)test_vectors[vec_num].cred_r;
	cred_r.g.len = test_vectors[vec_num].g_r_raw_len;
	cred_r.g.ptr = (uint8_t *)test_vectors[vec_num].g_r_raw;
	cred_r.pk.len = test_vectors[vec_num].pk_r_raw_len;
	cred_r.pk.ptr = (uint8_t *)test_vectors[vec_num].pk_r_raw;
	cred_r.ca.len = test_vectors[vec_num].ca_len;
	cred_r.ca.ptr = (uint8_t *)test_vectors[vec_num].ca;
	cred_r.ca_pk.len = test_vectors[vec_num].ca_pk_len;
	cred_r.ca_pk.ptr = (uint8_t *)test_vectors[vec_num].ca_pk;

	if (test_vectors[vec_num].c_i_raw != NULL) {
		c_i.c_i.type = BSTR;
		c_i.c_i.mem.c_x_bstr.len = test_vectors[vec_num].c_i_raw_len;
		c_i.c_i.mem.c_x_bstr.ptr =
			(uint8_t *)test_vectors[vec_num].c_i_raw;
	} else {
		c_i.c_i.type = INT;
		c_i.c_i.mem.c_x_int = *test_vectors[vec_num].c_i_raw_int;
	}
	c_i.msg4 = true;
	c_i.method = *test_vectors[vec_num].method;
	c_i.suites_i.len = test_vectors[vec_num].suites_i_len;
	c_i.suites_i.ptr = (uint8_t *)test_vectors[vec_num].suites_i;
	c_i.ead_1.len = test_vectors[vec_num].ead_1_len;
	c_i.ead_1.ptr = (uint8_t *)test_vectors[vec_num].ead_1;
	c_i.ead_3.len = test_vectors[vec_num].ead_3_len;
	c_i.ead_3.ptr = (uint8_t *)test_vectors[vec_num].ead_3;
	c_i.id_cred_i.len = test_vectors[vec_num].id_cred_i_len;
	c_i.id_cred_i.ptr = (uint8_t *)test_vectors[vec_num].id_cred_i;
	c_i.cred_i.len = test_vectors[vec_num].cred_i_len;
	c_i.cred_i.ptr = (uint8_t *)test_vectors[vec_num].cred_i;
	c_i.g_x.len = test_vectors[vec_num].g_x_raw_len;
	c_i.g_x.ptr = (uint8_t *)test_vectors[vec_num].g_x_raw;
	c_i.x.len = test_vectors[vec_num].x_raw_len;
	c_i.x.ptr = (uint8_t *)test_vectors[vec_num].x_raw;
	c_i.g_i.len = test_vectors[vec_num].g_i_raw_len;
	c_i.g_i.ptr = (uint8_t *)test_vectors[vec_num].g_i_raw;
	c_i.i.len = test_vectors[vec_num].i_raw_len;
	c_i.i.ptr = (uint8_t *)test_vectors[vec_num].i_raw;
	c_i.sk_i.len = test_vectors[vec_num].sk_i_raw_len;
	c_i.sk_i.ptr = (uint8_t *)test_vectors[vec_num].sk_i_raw;
	c_i.pk_i.len = test_vectors[vec_num].pk_i_raw_len;
	c_i.pk_i.ptr = (uint8_t *)test_vectors[vec_num].pk_i_raw;

	err = edhoc_initiator_run(&c_i, &cred_r, cred_num, err_msg,
				  &err_msg_len, ad_2, &ad_2_len, ad_4,
				  &ad_4_len, PRK_4x3m, sizeof(PRK_4x3m), th4,
				  sizeof(th4), tx, rx);
	if (r != ok) {
		PRINTK("error initiator run (Error Code %d\n)", r);
	}

	/* Print EDHOC output */
	PRINTK("PRK_4x3m: (size: %d)\n", sizeof(PRK_4x3m));
	for (int i = 0; i < sizeof(PRK_4x3m); i++) {
		if (i % 16 == 0)
			PRINTK("\n");
		else if (i % 8 == 0)
			PRINTK("   ");
		PRINTK("%02hhX ", PRK_4x3m[i]);
	}
	PRINTK("\n\n");
	PRINTK("th4: (size: %d)\n", sizeof(th4));
	for (int i = 0; i < sizeof(th4); i++) {
		if (i % 16 == 0)
			PRINTK("\n");
		else if (i % 8 == 0)
			PRINTK("   ");
		PRINTK("%02hhX ", th4[i]);
	}
	PRINTK("\n\n");

	/* run edhoc exporter here to extract OSCORE secrets */
}

/* Create thread for EDHOC */
K_THREAD_DEFINE(edhoc_thread, //name
		4608, //stack_size
		edhoc_initiator_init, //entry_function
		NULL, NULL, NULL, //parameter1,parameter2,parameter3
		5, //priority
		0, //options
		1000); //delay

/**
 * @brief	Receives and replies a UDP message in order to check the connection
 * 			This function is required since it may happen that the router 
 * 			is not set up at the moment when we want to send a message
 * @param	sock the socket's fd
 * @retval	error code
 */
static int check_router_connection(int sock)
{
	uint8_t data[30];
	struct sockaddr client_addr;
	socklen_t client_addr_len;

	int rcvd = recvfrom(sock, data, sizeof(data), 0, &client_addr,
			    &client_addr_len);
	if (rcvd >= 0) {
		PRINTK("%s\n", data);
		PRINTK("sending connection confirmation message...\n");
		sendto(sock, &data, rcvd, 0, &client_addr, client_addr_len);
	} else {
		PRINTK("error");
		return -errno;
	}

	return 0;
}

/**
 * @brief	Initializes sockets
 * @param	sock pointer to the socket's fd
 * @param	dev_type SERVER or client
 * @param
 * @retval	error code
 */
static int socket_init(int *sock, enum dev_type type, const char *addr)
{
	struct sockaddr_in6 addr6;
	int r;

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(PEER_PORT);

	r = inet_pton(AF_INET6, addr, &addr6.sin6_addr);
	if (r < 0)
		return -errno;

	*sock = socket(addr6.sin6_family, SOCK_DGRAM, IPPROTO_UDP);
	if (*sock < 0)
		return -errno;

	switch (type) {
	case CLIENT:
		/* The EDHOC initiator acts as a CoAP client. 
			 * We use the address of the CoAP server running at the backend */
		r = connect(*sock, (struct sockaddr *)&addr6, sizeof(addr6));
		if (r < 0)
			return -errno;
		break;
	case SERVER:
		/* We use a UDP server only for confirming that the connection to the router works. 
			 * We bind with the local address */
		r = bind(*sock, (struct sockaddr *)&addr6, sizeof(addr6));
		if (r < 0)
			return -errno;
		break;
	default:
		break;
	}

	return 0;
}

/**
 * @brief	Receives CoAP message from network and passes payload to callee
 * @param	sock the socket's fd
 * @param	msg pointer to store the received payload
 * @param	msg_len length of the received payload
 * @param
 * @retval	error code
 */
static int process_simple_coap_reply(int sock, const uint8_t **msg,
				     uint16_t *msg_len)
{
	struct coap_packet reply;
	uint8_t *data;
	int rcvd;
	const uint8_t *payload;
	uint16_t payload_len;
	int ret;

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data)
		return -ENOMEM;

	rcvd = recv(sock, data, MAX_COAP_MSG_LEN, 0);
	if (rcvd == 0) {
		PRINTK("error during receive\n");
		ret = -EIO;
		goto end;
	}

	if (rcvd < 0) {
		if (errno == EAGAIN || errno == EWOULDBLOCK) {
			ret = 0;
		} else {
			ret = -errno;
		}
		PRINTK("receive form socket error %d", rcvd);
		goto end;
	}

	net_hexdump("Response", data, rcvd);

	ret = coap_packet_parse(&reply, data, rcvd, NULL, 0);
	if (ret < 0) {
		LOG_ERR("Invalid data received");
	}

	payload = coap_packet_get_payload(&reply, &payload_len);
	if (payload) {
		net_hexdump("POST Payload:", payload, payload_len);
	}

	*msg = payload;
	*msg_len = payload_len;

end:
	k_free(data);

	return ret;
}

/**
 * @brief	Send CoAP request over network
 * @param	sock pointer to the socket's fd
 * @param	method desired CoAP method
 * @param	msg payload of message to be sent
 * @param	msg_len length of payload of message
 * @retval	error code
 */
static int send_simple_coap_request(int sock, uint8_t method, uint8_t *msg,
				    uint32_t msg_len)
{
	/* CoAP Options */
	static const uint8_t *edhoc_path = ".well-known/edhoc";
	struct coap_packet request;
	uint8_t *data;
	int r;

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_packet_init(&request, data, MAX_COAP_MSG_LEN, 1, COAP_TYPE_CON,
			     8, coap_next_token(), method, coap_next_id());
	if (r < 0) {
		LOG_ERR("Failed to init CoAP message");
		goto end;
	}

	r = coap_packet_append_option(&request, COAP_OPTION_URI_PATH,
				      edhoc_path, strlen(edhoc_path));
	if (r < 0) {
		LOG_ERR("Failed to init CoAP message");
		goto end;
	}

	r = coap_packet_append_payload_marker(&request);
	if (r < 0) {
		LOG_ERR("Unable to append payload marker");
		goto end;
	}

	r = coap_packet_append_payload(&request, msg, msg_len);
	if (r < 0) {
		LOG_ERR("Not able to append payload");
		goto end;
	}

	net_hexdump("Request", request.data, request.offset);

	r = send(sock, request.data, request.offset, 0);
	if (r < 0) {
		PRINTK("error during sending\n");
		goto end;
	}

	return 0;

end:
	k_free(data);
	return r;
}

/**
 * @brief	Handles message transfer between EDHOC thread and network
 * @param	sock the socket's fd
 * @param
 * @retval	error code
 */
static int txrx_edhoc(int sock)
{
	int r;
	struct k_mbox_msg send_msg;
	struct k_mbox_msg recv_msg;
	char buffer[MBOX_MSG_SIZE];
	int buffer_bytes_used;
	const uint8_t *msg;
	uint16_t msg_len;

	/* wait for msg1 from edhoc_thread */
	send_msg.info = MBOX_MSG_SIZE;
	send_msg.size = MBOX_MSG_SIZE;
	send_msg.rx_source_thread = K_ANY;
	k_mbox_get(&tx_queue, &send_msg, buffer, K_SECONDS(MBOX_WAIT_TIME));
	if (send_msg.info != send_msg.size) {
		PRINTK("some message data dropped during transfer!\n");
		PRINTK("sender tried to send %d bytes\n", send_msg.info);
	}

	/* Send msg1 as CoAP POST */
	PRINTK("Send CoAP POST MSG1\n");
	PRINT_ARRAY("MSG1", buffer, send_msg.size);
	r = send_simple_coap_request(sock, COAP_METHOD_POST, buffer,
				     send_msg.size);
	if (r < 0)
		return r;

	/*get msg2 over the network */
	r = process_simple_coap_reply(sock, &msg, &msg_len);
	if (r < 0)
		return r;

	/* give msg2 to edhoc_thread */
	buffer_bytes_used = msg_len;
	memcpy(buffer, msg, buffer_bytes_used);
	recv_msg.info = buffer_bytes_used;
	recv_msg.size = buffer_bytes_used;
	recv_msg.tx_data = buffer;
	recv_msg.tx_block.data = NULL;
	recv_msg.tx_target_thread = K_ANY;
	k_mbox_put(&rx_queue, &recv_msg, K_FOREVER);
	if (recv_msg.size < buffer_bytes_used) {
		PRINTK("some message data dropped during transfer!");
		PRINTK("receiver only had room for %d bytes\n", recv_msg.info);
	}

	/* wait for msg3 from edhoc_thread */
	send_msg.info = MBOX_MSG_SIZE;
	send_msg.size = MBOX_MSG_SIZE;
	send_msg.rx_source_thread = K_ANY;
	k_mbox_get(&tx_queue, &send_msg, buffer, K_SECONDS(MBOX_WAIT_TIME));
	if (send_msg.info != send_msg.size) {
		PRINTK("some message data dropped during transfer!\n");
		PRINTK("sender tried to send %d bytes\n", send_msg.info);
	}

	/* Send msg3 as CoAP POST */
	PRINTK("Send CoAP POST MSG3\n");
	PRINT_ARRAY("MSG3", buffer, send_msg.size);
	r = send_simple_coap_request(sock, COAP_METHOD_POST, buffer,
				     send_msg.size);
	if (r < 0)
		return r;

	r = process_simple_coap_reply(sock, &msg, &msg_len);
	if (r < 0)
		return r;

	return 0;
}

void main(void)
{
	int r;

	/* This is the socket of the peer */
	static int peer_sock;
	/*This is the socket of the BLE router. We use this socket only to check if we are connected*/
	static int rpi_sock;

	r = socket_init(&peer_sock, CLIENT, CONFIG_NET_CONFIG_PEER_IPV6_ADDR);
	if (r < 0)
		goto quit;
	r = socket_init(&rpi_sock, SERVER, CONFIG_NET_CONFIG_MY_IPV6_ADDR);
	if (r < 0)
		goto quit;

	r = check_router_connection(rpi_sock);
	if (r < 0)
		goto quit;

	r = txrx_edhoc(peer_sock);
	if (r < 0)
		goto quit;

quit:
	/* Close the sockets */
	(void)close(peer_sock);
	(void)close(rpi_soc);
}
