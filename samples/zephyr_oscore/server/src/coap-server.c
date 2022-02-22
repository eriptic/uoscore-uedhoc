/*
 * Copyright (c) 2018 Intel Corporation
 *
 * SPDX-License-Identifier: Apache-2.0
 */
#include <logging/log.h>
#include <stdio.h>
LOG_MODULE_REGISTER(net_coap_server_sample, LOG_LEVEL_DBG);

#include <errno.h>
#include <net/coap.h>
#include <net/coap_link_format.h>
#include <net/net_ip.h>
#include <net/net_mgmt.h>
#include <net/socket.h>
#include <net/udp.h>
#include <oscore.h>
#include <stdint.h>
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

/* block option helper */
//#define GET_BLOCK_NUM(v) ((v) >> 4)
//#define GET_BLOCK_SIZE(v) (((v)&0x7))
//#define GET_MORE(v) (!!((v)&0x08))

/* CoAP socket fd */
static int sock;

static const uint8_t plain_text_format;

static struct coap_observer observers[NUM_OBSERVERS];

static struct coap_pending pendings[NUM_PENDINGS];

static struct k_delayed_work observer_work;

static int obs_counter;

static struct coap_resource *resource_to_notify;

static struct k_delayed_work retransmit_work;

/* Oscore global variables */
#ifdef OSCORE_PSK
struct context c;
static bool oscore_pkg_flag;
#endif

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
static int start_coap_server(void)
{
	struct sockaddr_in6 addr6;
	int r;

	memset(&addr6, 0, sizeof(addr6));
	addr6.sin6_family = AF_INET6;
	addr6.sin6_port = htons(MY_COAP_PORT);

	sock = zsock_socket(addr6.sin6_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket %d", errno);
		return -errno;
	}

	r = zsock_bind(sock, (struct sockaddr *)&addr6, sizeof(addr6));
	if (r < 0) {
		LOG_ERR("Failed to bind UDP socket %d", errno);
		return -errno;
	}

	return 0;
}
#endif

#if defined(CONFIG_NET_IPV4)
static int start_coap_server(void)
{
	struct sockaddr_in addr;
	int r;

	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(MY_COAP_PORT);
	addr.sin_addr.s_addr = htonl(INADDR_ANY); //inet_addr("127.0.0.1");

	sock = zsock_socket(addr.sin_family, SOCK_DGRAM, IPPROTO_UDP);
	if (sock < 0) {
		LOG_ERR("Failed to create UDP socket %d", errno);
		return -errno;
	}

	r = zsock_bind(sock, (struct sockaddr *)&addr, sizeof(addr));
	if (r < 0) {
		LOG_ERR("Failed to bind UDP socket %d", errno);
		return -errno;
	}

	return 0;
}
#endif

static int send_coap_reply(struct coap_packet *cpkt,
			   const struct sockaddr *addr, socklen_t addr_len)
{
	int r;

	net_hexdump("Response", cpkt->data, cpkt->offset);

	r = zsock_sendto(sock, cpkt->data, cpkt->offset, 0, addr, addr_len);
	if (r < 0) {
		LOG_ERR("Failed to send %d", errno);
		r = -errno;
	}

	return r;
}

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

static int oscore_secured_get(struct coap_resource *resource,
			      struct coap_packet *request,
			      struct sockaddr *addr, socklen_t addr_len)
{
	struct coap_packet response;
	uint8_t token[8];
	uint8_t *data;
	uint16_t id;
	uint8_t code;
	uint8_t type;
	uint8_t tkl;
	int r;

	code = coap_header_get_code(request);
	type = coap_header_get_type(request);
	id = coap_header_get_id(request);
	tkl = coap_header_get_token(request, token);

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
			     (uint8_t *)token, COAP_RESPONSE_CODE_CONTENT, id);
	if (r < 0) {
		goto end;
	}

	r = coap_packet_append_option(&response, COAP_OPTION_CONTENT_FORMAT,
				      &plain_text_format,
				      sizeof(plain_text_format));
	if (r < 0) {
		goto end;
	}

	r = coap_packet_append_payload_marker(&response);
	if (r < 0) {
		goto end;
	}

	if (oscore_pkg_flag) {
		/* we received an OSCORE packet */
		LOG_DBG("Received OSCORE secured packet\n");

		uint8_t buf_oscore[256];
		uint16_t buf_oscore_len = sizeof(buf_oscore);
		uint8_t secret_payload[] = { "Secret Mesg!" };

		r = coap_packet_append_payload(&response, secret_payload,
					       strlen(secret_payload));
		if (r < 0) {
			goto end;
		}

		coap2oscore(response.data, response.offset, buf_oscore,
			    &buf_oscore_len, &c);

		net_hexdump("Response", buf_oscore, buf_oscore_len);

		r = zsock_sendto(sock, buf_oscore, buf_oscore_len, 0, addr,
				 addr_len);
		if (r < 0) {
			LOG_ERR("Failed to send %d", errno);
			r = -errno;
			goto end;
		}
	} else {
		/* we received a regular CoAP packet */
		LOG_DBG("Received regular CoAP packet\n");

		uint8_t payload[] = { "Visible Mesg" };

		r = coap_packet_append_payload(&response, payload,
					       strlen(payload));

		if (r < 0) {
			goto end;
		}

		r = send_coap_reply(&response, addr, addr_len);
	}

end:
	k_free(data);

	return r;
}

static int edhoc_post(struct coap_resource *resource,
		      struct coap_packet *request, struct sockaddr *addr,
		      socklen_t addr_len)
{
	static const char *const location_path[] = { "location1", "location2",
						     "location3", NULL };
	const char *const *p;
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
			     (uint8_t *)token, COAP_RESPONSE_CODE_CREATED, id);
	if (r < 0) {
		goto end;
	}

	for (p = location_path; *p; p++) {
		r = coap_packet_append_option(
			&response, COAP_OPTION_LOCATION_PATH, *p, strlen(*p));
		if (r < 0) {
			goto end;
		}
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

static const char *const edhoc_path[] = { "edhoc", NULL };

static const char *const oscore_secured_path[] = { "tv1", NULL };

static struct coap_resource resources[] = {
	{
		.get = well_known_core_get,
		.path = COAP_WELL_KNOWN_CORE_PATH,
	},
	{
		.get = oscore_secured_get,
		.path = oscore_secured_path,
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
	uint8_t decrypted_oscore[MAX_COAP_MSG_LEN];
	uint16_t decrypted_oscore_len;

	r = oscore2coap(data, data_len, decrypted_oscore, &decrypted_oscore_len,
			&oscore_pkg_flag, &c);

	if (r < 0) {
		LOG_ERR("OSCORE error (%d)\n", r);
		return;
	}

	if (oscore_pkg_flag) {
		r = coap_packet_parse(&request, decrypted_oscore,
				      decrypted_oscore_len, options, opt_num);
		if (r < 0) {
			LOG_ERR("Invalid data received (%d)\n", r);
			return;
		}
	} else {
		r = coap_packet_parse(&request, data, data_len, options,
				      opt_num);
		if (r < 0) {
			LOG_ERR("Invalid data received (%d)\n", r);
			return;
		}
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

static int process_client_request(void)
{
	int received;
	struct sockaddr client_addr;
	socklen_t client_addr_len;
	uint8_t request[MAX_COAP_MSG_LEN];

	do {
		client_addr_len = sizeof(client_addr);

		received = zsock_recvfrom(sock, request, sizeof(request), 0,
					  &client_addr, &client_addr_len);

		if (received < 0) {
			LOG_ERR("Connection error %d", errno);
			return -errno;
		}

		for (int i = 0; i < received; i++) {
			LOG_DBG("%c", request[i]);
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

#ifdef OSCORE_PSK
	struct oscore_init_params params = {
		.dev_type = SERVER,
		.master_secret.ptr = MASTER_SECRET,
		.master_secret.len = MASTER_SECRET_LEN,
		.sender_id.ptr = SENDER_ID,
		.sender_id.len = SENDER_ID_LEN,
		.recipient_id.ptr = RECIPIENT_ID,
		.recipient_id.len = RECIPIENT_ID_LEN,
		.id_context.ptr = ID_CONTEXT,
		.id_context.len = ID_CONTEXT_LEN,
		.master_salt.ptr = MASTER_SALT,
		.master_salt.len = MASTER_SALT_LEN,
		.aead_alg = AES_CCM_16_64_128,
		.hkdf = SHA_256,
		//.replaw_window = NULL, /*not implemented*/
	};

	r = oscore_context_init(&params, &c);

	if (r != ok) {
		LOG_DBG("Error during establishing an OSCORE security context!\n");
		goto quit;
	} else {
		LOG_DBG("OSCORE security context successfully initialized\n");
	}
#endif

	r = start_coap_server();
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
