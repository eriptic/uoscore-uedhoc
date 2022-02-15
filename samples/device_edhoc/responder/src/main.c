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
LOG_MODULE_REGISTER(net_coap_server_sample, LOG_LEVEL_DBG);

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

#include "credentials.h"
#include "net_private.h"

#define MAX_COAP_MSG_LEN 256

#define MY_COAP_PORT 5683

#define BLOCK_WISE_TRANSFER_SIZE_GET 2048

#if defined(CONFIG_NET_IPV6)
#define ALL_NODES_LOCAL_COAP_MCAST                                             \
	{                                                                      \
		{                                                              \
			{                                                      \
				0xff, 0x02, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0,   \
					0, 0, 0xfd                             \
			}                                                      \
		}                                                              \
	}

#define MY_IP6ADDR                                                             \
	{                                                                      \
		{                                                              \
			{                                                      \
				0x20, 0x01, 0x0d, 0xb8, 0, 0, 0, 0, 0, 0, 0,   \
					0, 0, 0, 0, 0x1                        \
			}                                                      \
		}                                                              \
	}
#endif

#define NUM_OBSERVERS 3

#define NUM_PENDINGS 3

/* Uncomment the following line to enable printf output */
//#define ENABLE_PRINTK
#ifdef ENABLE_PRINTK
#define PRINTK(text, ...) printk(text, ##__VA_ARGS__)
#else
#define PRINTK(text, ...)
#endif

/* create queues for EDHOC */
#define MBOX_MSG_SIZE 300
#define MBOX_WAIT_TIME 20
K_MBOX_DEFINE(rx_queue);
K_MBOX_DEFINE(tx_queue);

/**
 * @brief	Entry function of EDHOC thread. Starts EDHOC responder.
 * @param
 * @retval	none
 */
void edhoc_responder_init(void)
{
	err r;

	/* Edhoc internal parameters */
	uint8_t PRK_4x3m[PRK_DEFAULT_SIZE];
	uint8_t th4[SHA_DEFAULT_SIZE];
	uint8_t err_msg[ERR_MSG_DEFAULT_SIZE];
	uint32_t err_msg_len = sizeof(err_msg);
	struct other_party_cred cred_i = { .id_cred.ptr = ID_CRED_I,
					   .id_cred.len = ID_CRED_I_LEN,
					   .cred.ptr = CRED_I,
					   .cred.len = CRED_I_LEN,
					   .pk.ptr = PK_I,
					   .pk.len = PK_I_LEN,
					   .g.ptr = G_I,
					   .g.len = G_I_LEN,
					   .ca.ptr = CA,
					   .ca.len = CA_LEN,
					   .ca_pk.ptr = CA_PK,
					   .ca_pk.len = CA_PK_LEN };
	struct edhoc_responder_context c_r = { .suites_r.ptr = SUITES_R,
					       .suites_r.len = SUITES_R_LEN,
					       .g_y.ptr = G_Y,
					       .g_y.len = G_Y_LEN,
					       .y.ptr = Y,
					       .y.len = Y_LEN,
					       .c_r.ptr = C_R,
					       .c_r.len = C_R_LEN,
					       .ad_2.ptr = AD_2,
					       .ad_2.len = AD_2_LEN,
					       .id_cred_r.ptr = ID_CRED_R,
					       .id_cred_r.len = ID_CRED_R_LEN,
					       .cred_r.ptr = CRED_R,
					       .cred_r.len = CRED_R_LEN,
					       .sk_r.ptr = SK_R,
					       .sk_r.len = SK_R_LEN,
					       .pk_r.ptr = PK_R,
					       .pk_r.len = PK_R_LEN,
					       .r.ptr = R,
					       .r.len = R_LEN,
					       .g_r.ptr = G_R,
					       .g_r.len = G_R_LEN };
	uint8_t ad_1[AD_DEFAULT_SIZE];
	uint64_t ad_1_len = sizeof(ad_1);
	uint8_t ad_3[AD_DEFAULT_SIZE];
	uint64_t ad_3_len = sizeof(ad_3);

	while (1) {
		r = edhoc_responder_run(&c_r, &cred_i, 1, err_msg, &err_msg_len,
					(uint8_t *)&ad_1, &ad_1_len,
					(uint8_t *)&ad_3, &ad_3_len, PRK_4x3m,
					sizeof(PRK_4x3m), th4, sizeof(th4));
		if (r != ok) {
			PRINTK("error responder run (Error Code %d)\n", r);
		}

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
}

/* create thread for EDHOC */
K_THREAD_DEFINE(edhoc_thread, //name
		4608, //stack_size
		edhoc_responder_init, //entry_function
		NULL, NULL, NULL, //parameter1,parameter2,parameter3
		0, //priority
		0, //options
		0); //delay

/* CoAP socket fd */
static int sock;

static struct coap_observer observers[NUM_OBSERVERS];

static struct coap_pending pendings[NUM_PENDINGS];

static struct k_delayed_work observer_work;

static int obs_counter;

static struct coap_resource *resource_to_notify;

static struct k_delayed_work retransmit_work;

#if defined(CONFIG_NET_IPV6)
static bool join_coap_multicast_group(void)
{
	static struct in6_addr my_addr = MY_IP6ADDR;
	static struct sockaddr_in6 mcast_addr = {
		.sin6_family = AF_INET6,
		.sin6_addr = ALL_NODES_LOCAL_COAP_MCAST,
		.sin6_port = htons(MY_COAP_PORT)
	};
	struct net_if_mcast_addr *mcast;
	struct net_if_addr *ifaddr;
	struct net_if *iface;

	iface = net_if_get_default();
	if (!iface) {
		LOG_ERR("Could not get te default interface\n");
		return false;
	}

#if defined(CONFIG_NET_CONFIG_SETTINGS)
	if (net_addr_pton(AF_INET6, CONFIG_NET_CONFIG_MY_IPV6_ADDR, &my_addr) <
	    0) {
		LOG_ERR("Invalid IPv6 address %s",
			CONFIG_NET_CONFIG_MY_IPV6_ADDR);
	}
#endif

	ifaddr = net_if_ipv6_addr_add(iface, &my_addr, NET_ADDR_MANUAL, 0);
	if (!ifaddr) {
		LOG_ERR("Could not add unicast address to interface");
		return false;
	}

	ifaddr->addr_state = NET_ADDR_PREFERRED;

	mcast = net_if_ipv6_maddr_add(iface, &mcast_addr.sin6_addr);
	if (!mcast) {
		LOG_ERR("Could not add multicast address to interface\n");
		return false;
	}

	return true;
}
#endif

#if defined(CONFIG_NET_IPV6)
/**
 * @brief	Initializes sockets for CoAP server (IPv6)
 * @param
 * @retval	error code
 */
static int start_coap_server(void)
{
	struct sockaddr_in6 addr6;
	int r;

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(MY_COAP_PORT);

	sock = socket(addr6.sin6_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket %d", errno);
		return -errno;
	}

	r = bind(sock, (struct sockaddr *)&addr6, sizeof(addr6));
	if (r < 0) {
		LOG_ERR("Failed to bind UDP socket %d", errno);
		return -errno;
	}

	return 0;
}
#endif

#if defined(CONFIG_NET_IPV4)
/**
 * @brief	Initializes sockets for CoAP server (IPv4)
 * @param
 * @retval	error code
 */
static int start_coap_server(void)
{
	struct sockaddr_in addr;
	int r;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(MY_COAP_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY); //inet_addr("127.0.0.1");

	sock = socket(addr.sin_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket %d", errno);
		return -errno;
	}

	r = bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (r < 0) {
		LOG_ERR("Failed to bind UDP socket %d", errno);
		return -errno;
	}

	return 0;
}
#endif

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
	client_addr_len = sizeof(client_addr);

	int rcvd = recvfrom(sock, data, sizeof(data), 0, &client_addr,
			    &client_addr_len);
	if (rcvd >= 0) {
		PRINTK("%s\n", data);
		PRINTK("sending connection confirmation message...\n");
		sendto(sock, &data, rcvd, 0, &client_addr, client_addr_len);
	} else {
		PRINTK("error (%d)\n", errno);
		return -errno;
	}

	return 0;
}

/**
 * @brief	Sends CoAP reply packet over network
 * @param	cpkt CoAP packet to be sent 
 * @param	addr client address (destination)
 * @param	addr_len length of client address
 * @retval	error code
 */
static int send_coap_reply(struct coap_packet *cpkt,
			   const struct sockaddr *addr, socklen_t addr_len)
{
	int r;

	net_hexdump("Response", cpkt->data, cpkt->offset);

	GPIO_HIGH(LED1);
	r = sendto(sock, cpkt->data, cpkt->offset, 0, addr, addr_len);
	if (r < 0) {
		LOG_ERR("Failed to send %d", errno);
		r = -errno;
	}
	GPIO_LOW(LED1);

	return r;
}

/**
 * @brief	Reveals available resources to client (see RFC7252 for details)
 * @param	resource requested resource(s)
 * @param	request CoAP client request packet
 * @param	addr client address (destination)
 * @param	addr_len length of client address 
 * @retval	error code
 */
static int well_known_core_get(struct coap_resource *resource,
			       struct coap_packet *request,
			       struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_packet response;
	uint8_t *data;
	int r;

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_well_known_core_get(resource, request, &response, data,
				     MAX_COAP_MSG_LEN);
	if (r < 0) {
		goto end;
	}

	r = send_coap_reply(&response, addr, addr_len);

end:
	k_free(data);

	return r;
}

/**
 * @brief	Callback for EDHOC Post request. Passes request payload to EDHOC thread 
 * 			and waits for EDHOC response message.
 * @param	resource requested resource
 * @param	request CoAP client request packet
 * @param	addr client address (destination)
 * @param	addr_len length of client address 
 * @retval	error code
 */
static int edhoc_post(struct coap_resource *resource,
		      struct coap_packet *request, struct sockaddr *addr,
		      socklen_t addr_len)
{
	struct coap_packet response;
	uint8_t token[8];
	const uint8_t *payload;
	uint8_t *data;
	uint16_t payload_len;
	uint8_t code;
	uint8_t type;
	uint8_t tkl;
	uint16_t id;
	int r;
	struct k_mbox_msg recv_msg; //edhoc post payload
	struct k_mbox_msg send_msg; //edhoc response
	char buffer[MBOX_MSG_SIZE];
	int buffer_bytes_used;
	uint8_t finished_indicator[] = { "EDHOC successful" };
	static int msg_count = 1;

	code = coap_header_get_code(request);
	type = coap_header_get_type(request);
	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

	LOG_INF("*******");
	LOG_INF("type: %u code %u id %u", type, code, id);
	LOG_INF("*******");

	payload = coap_packet_get_payload(request, &payload_len);
	if (payload) {
		net_hexdump("POST Payload", payload, payload_len);
	}

	/* prepare message box packet to send to edhoc thread */
	buffer_bytes_used = payload_len;
	memcpy(buffer, payload, buffer_bytes_used);
	recv_msg.info = buffer_bytes_used;
	recv_msg.size = buffer_bytes_used;
	recv_msg.tx_data = buffer;
	recv_msg.tx_block.data = NULL;
	recv_msg.tx_target_thread = K_ANY;
	k_mbox_put(&rx_queue, &recv_msg, K_FOREVER);
	if (recv_msg.size < buffer_bytes_used) {
		PRINTK("some message data dropped during transfer!");
		PRINTK("receiver only had room for %d bytes", send_msg.info);
	}

	/* wait for data from edhoc_thread */
	send_msg.info = MBOX_MSG_SIZE;
	send_msg.size = MBOX_MSG_SIZE;
	send_msg.rx_source_thread = K_ANY;
	k_mbox_get(&tx_queue, &send_msg, buffer, K_SECONDS(MBOX_WAIT_TIME));
	if (send_msg.info != send_msg.size) {
		PRINTK("some message data dropped during transfer!");
		PRINTK("sender tried to send %d bytes", send_msg.info);
	}

	if (type == COAP_TYPE_CON) {
		type = COAP_TYPE_ACK;
	} else {
		type = COAP_TYPE_NON_CON;
	}

	data = (uint8_t *)k_malloc(MAX_COAP_MSG_LEN);
	if (!data) {
		return -ENOMEM;
	}

	r = coap_packet_init(&response, data, MAX_COAP_MSG_LEN, 1, type, tkl,
			     (uint8_t *)token, COAP_RESPONSE_CODE_CHANGED, id);
	if (r < 0) {
		goto end;
	}

	/* check if msg2 or edhoc finished */
	if (memcmp(buffer, finished_indicator, sizeof(finished_indicator)) !=
	    0) {
		r = coap_packet_append_payload_marker(&response);
		if (r < 0) {
			goto end;
		}

		r = coap_packet_append_payload(&response, buffer,
					       send_msg.size);
		if (r < 0) {
			goto end;
		}
		msg_count++;
	} else {
		msg_count = 1;
	}

	r = send_coap_reply(&response, addr, addr_len);

end:
	k_free(data);

	return r;
}

static void retransmit_request(struct k_work *work)
{
	struct coap_pending *pending;

	pending = coap_pending_next_to_expire(pendings, NUM_PENDINGS);
	if (!pending) {
		return;
	}

	if (!coap_pending_cycle(pending)) {
		k_free(pending->data);
		coap_pending_clear(pending);
		return;
	}

	k_delayed_work_submit(&retransmit_work, K_MSEC(pending->timeout));
}

static void update_counter(struct k_work *work)
{
	obs_counter++;

	if (resource_to_notify) {
		coap_resource_notify(resource_to_notify);
	}

	k_delayed_work_submit(&observer_work, K_SECONDS(5));
}

static const char *const edhoc_path[] = { ".well-known", "edhoc", NULL };

static struct coap_resource resources[] = {
	{
		.get = well_known_core_get,
		.path = COAP_WELL_KNOWN_CORE_PATH,
	},
	{
		.post = edhoc_post,
		.path = edhoc_path,
	},
	{},
};

static struct coap_resource *
find_resource_by_observer(struct coap_resource *resources,
			  struct coap_observer *o)
{
	struct coap_resource *r;

	for (r = resources; r && r->path; r++) {
		sys_snode_t *node;

		SYS_SLIST_FOR_EACH_NODE (&r->observers, node) {
			if (&o->list == node) {
				return r;
			}
		}
	}

	return NULL;
}

/**
 * @brief	Parses CoAP client request and calls handler of requested resource.
 * @param	data received CoAP client request
 * @param	data_len length of received CoAP client request
 * @param	addr client address (destination)
 * @param	addr_len length of client address 
 * @retval	error code
 */
static void process_coap_request(uint8_t *data, uint16_t data_len,
				 struct sockaddr *client_addr,
				 socklen_t client_addr_len)
{
	struct coap_packet request;
	struct coap_pending *pending;
	struct coap_option options[16] = { 0 };
	uint8_t opt_num = 16U;
	uint8_t type;
	int r;

	r = coap_packet_parse(&request, data, data_len, options, opt_num);
	if (r < 0) {
		LOG_ERR("Invalid data received (%d)\n", r);
	}

	type = coap_header_get_type(&request);

	pending = coap_pending_received(&request, pendings, NUM_PENDINGS);
	if (!pending) {
		goto not_found;
	}

	/* Clear CoAP pending request */
	if (type == COAP_TYPE_ACK) {
		k_free(pending->data);
		coap_pending_clear(pending);
	}

	return;

not_found:

	if (type == COAP_TYPE_RESET) {
		struct coap_resource *r;
		struct coap_observer *o;

		o = coap_find_observer_by_addr(observers, NUM_OBSERVERS,
					       client_addr);
		if (!o) {
			LOG_ERR("Observer not found\n");
			goto end;
		}

		r = find_resource_by_observer(resources, o);
		if (!r) {
			LOG_ERR("Observer found but Resource not found\n");
			goto end;
		}

		coap_remove_observer(r, o);

		return;
	}

end:

	r = coap_handle_request(&request, resources, options, opt_num,
				client_addr, client_addr_len);
	if (r < 0) {
		LOG_WRN("No handler for such request (%d)\n", r);
	}
}

/**
 * @brief	Waits for CoAP client request and passes received data to process_coap_request
 * @param	
 * @retval	error code
 */
static int process_client_request(void)
{
	int received;
	struct sockaddr client_addr;
	socklen_t client_addr_len;
	uint8_t request[MAX_COAP_MSG_LEN];

	do {
		client_addr_len = sizeof(client_addr);
		GPIO_HIGH(LED1);
		received = recvfrom(sock, request, sizeof(request), 0,
				    &client_addr, &client_addr_len);
		GPIO_LOW(LED1);
		if (received < 0) {
			LOG_ERR("Connection error %d", errno);
			return -errno;
		}

		process_coap_request(request, received, &client_addr,
				     client_addr_len);
	} while (true);

	return 0;
}

void main(void)
{
	int r;
	setbuf(stdout, NULL); //disable printf buffereing

	LOG_DBG("Start CoAP-server sample");

#ifdef CONFIG_NET_IPV6
	bool res;

	res = join_coap_multicast_group();
	if (!res) {
		goto quit;
	}
#endif

	LED_INIT();
	GPIO_LOW(LED0);
	GPIO_LOW(LED1);

	r = start_coap_server();
	if (r < 0) {
		goto quit;
	}

	r = check_router_connection(sock);
	if (r < 0) {
		goto quit;
	}

	k_delayed_work_init(&retransmit_work, retransmit_request);
	k_delayed_work_init(&observer_work, update_counter);

	while (1) {
		r = process_client_request();
		if (r < 0) {
			goto quit;
		}
	}

	LOG_DBG("Done");
	return;

quit:
	LOG_ERR("Quit");
}
