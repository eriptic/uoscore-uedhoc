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

#include "credentials.h"
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

/**
 * @brief	Entry function of EDHOC thread. Starts EDHOC initiator.
 * @param
 * @retval	none
 */
void edhoc_initiator_init(void)
{
	err r;
	uint8_t PRK_4x3m[PRK_DEFAULT_SIZE];
	uint8_t th4[SHA_DEFAULT_SIZE];
	uint8_t err_msg[ERR_MSG_DEFAULT_SIZE];
	uint32_t err_msg_len = sizeof(err_msg);
	struct other_party_cred cred_r = {
		.id_cred.ptr = ID_CRED_R,
		.id_cred.len = ID_CRED_R_LEN,
		.cred.ptr = CRED_R,
		.cred.len = CRED_R_LEN,
		.pk.ptr = PK_R,
		.pk.len = PK_R_LEN,
		.g.ptr = G_R,
		.g.len = G_R_LEN,
		.ca.ptr = CA,
		.ca.len = CA_LEN,
		.ca_pk.ptr = CA_PK,
		.ca_pk.len = CA_PK_LEN,
	};
	uint16_t cred_num = 1;
	struct edhoc_initiator_context c_i = {
		.method_type = METHOD_TYPE,
		.corr = CORR,
		.suites_i.ptr = SUITES_I,
		.suites_i.len = SUITES_I_LEN,
		.g_x.ptr = G_X,
		.g_x.len = G_X_LEN,
		.x.ptr = X,
		.x.len = X_LEN,
		.c_i.ptr = C_I,
		.c_i.len = C_I_LEN,
		.ad_1.ptr = AD_1,
		.ad_1.len = AD_1_LEN,
		.g_i.ptr = G_I,
		.g_i.len = G_I_LEN,
		.i.ptr = I,
		.i.len = I_LEN,
		.ad_3.ptr = AD_3,
		.ad_3.len = AD_3_LEN,
		.id_cred_i.ptr = ID_CRED_I,
		.id_cred_i.len = ID_CRED_I_LEN,
		.cred_i.ptr = CRED_I,
		.cred_i.len = CRED_I_LEN,
		.sk_i.ptr = SK_I,
		.sk_i.len = SK_I_LEN,
		.pk_i.ptr = PK_I,
		.pk_i.len = PK_I_LEN,
	};

	uint8_t ad_2[AD_DEFAULT_SIZE];
	uint64_t ad_2_len = sizeof(ad_2);

	r = edhoc_initiator_run(&c_i, &cred_r, cred_num, err_msg, &err_msg_len,
				ad_2, &ad_2_len, PRK_4x3m, sizeof(PRK_4x3m),
				th4, sizeof(th4));
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
