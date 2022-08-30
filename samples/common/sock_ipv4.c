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
#include <string.h>

#include <arpa/inet.h>
#include <sys/socket.h>

/**
 * @brief   Initializes a IPv4 client or server socket
 * @param   sock_t CLIENT or SERVER
 * @param   ipv6_addr_str ip address as string
 * @param   servaddr address struct 
 * @param   servaddr_len length of servaddr  
 * @param	sockfd socket file descriptor
 * @retval	error code
 */
int ipv4_sock_init(enum sock_type sock_t, const char *ipv4_addr_str,
		   struct sockaddr_in *servaddr, size_t servaddr_len,
		   int *sockfd)
{
	int r;

	memset(servaddr, 0, servaddr_len);

	/* Creating socket file descriptor */
	*sockfd = socket(AF_INET, SOCK_DGRAM, 0);
	if (*sockfd < 0)
		return *sockfd;

	servaddr->sin_family = AF_INET;
	servaddr->sin_port = htons(PORT);
	servaddr->sin_addr.s_addr = inet_addr(ipv4_addr_str);

	if (sock_t == SOCK_CLIENT) {
		r = connect(*sockfd, (const struct sockaddr *)servaddr,
			    servaddr_len);
		if (r < 0) {
			return r;
		}

		printf("IPv4 client to connect to server with address %s started!\n",
		       ipv4_addr_str);
	} else {
		r = bind(*sockfd, (const struct sockaddr *)servaddr,
			 servaddr_len);
		if (r < 0) {
			return r;
		}

		printf("IPv4 server with address %s started!\n", ipv4_addr_str);
	}
	return 0;
}
