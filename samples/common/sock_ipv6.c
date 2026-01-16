/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#include "sock.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#ifdef LINUX_SOCKETS
#include <arpa/inet.h>
#include <sys/socket.h>
#include <net/if.h>
#else
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/udp.h>
#include <zephyr/net/socket.h>
#endif

int ipv6_sock_init(enum sock_type sock_t, const char *ipv6_addr_str,
		   struct sockaddr_in6 *servaddr, size_t servaddr_len,
		   int *sockfd)
{
	int r;
	char* zone;
	unsigned int index;

	memset(servaddr, 0, servaddr_len);

	/* Creating socket file descriptor */
	*sockfd = socket(AF_INET6, SOCK_DGRAM, 0);
	if (*sockfd < 0)
		return *sockfd;

	servaddr->sin6_family = AF_INET6;
	servaddr->sin6_port = htons(PORT);

	/* Look for IPv6 zone identifier (RFC6874) */
	zone = strchr(ipv6_addr_str, '%');
	if (zone){
		*zone = '\0';
		zone++;

		index = if_nametoindex(zone);
		if (index == 0){
			/* zone could already be numerical index */
			index = atoi(zone);
			if (index == 0) {
				return -1;
			}
		}
		servaddr->sin6_scope_id = index;
	}
	r = inet_pton(AF_INET6, ipv6_addr_str, &servaddr->sin6_addr);
	if (r != 1)
		return r;

	if (sock_t == SOCK_CLIENT) {
		r = connect(*sockfd, (const struct sockaddr *)servaddr,
			    servaddr_len);
		if (r < 0)
			return r;
		printf("IPv6 client to connect to server with address %s started!\n",
		       ipv6_addr_str);
	} else {
		r = bind(*sockfd, (const struct sockaddr *)servaddr,
			 servaddr_len);
		if (r < 0)
			return r;

		printf("IPv6 server with address %s started!\n", ipv6_addr_str);
	}
	return 0;
}
