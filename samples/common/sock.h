/*
   Copyright (c) 2021 Fraunhofer AISEC. See the COPYRIGHT
   file at the top-level directory of this distribution.

   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/
#ifndef SOCK_H
#define SOCK_H

#include <stdint.h>
#include <stddef.h>

#ifdef LINUX_SOCKETS
#include <arpa/inet.h>
#include <sys/socket.h>
#else
#include <zephyr/net/net_pkt.h>
#include <zephyr/net/net_if.h>
#include <zephyr/net/net_core.h>
#include <zephyr/net/net_context.h>
#include <zephyr/net/udp.h>
#include <zephyr/net/socket.h>
#endif

#ifndef PORT
#define PORT 5683
#endif

#define MAXLINE 1024

enum sock_type {
	SOCK_CLIENT,
	SOCK_SERVER,
};

enum ip_addr_type {
	IPv4,
	IPv6,
};

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
		   int *sockfd);

/**
 * @brief   Initializes a IPv6 client or server socket
 * @param   sock_t CLIENT or SERVER
 * @param   ipv6_addr_str ip address as string
 * @param   servaddr address struct 
 * @param   servaddr_len length of servaddr  
 * @param	sockfd socket file descriptor
 * @retval	error code
 */
int ipv6_sock_init(enum sock_type sock_t, const char *ipv6_addr_str,
		   struct sockaddr_in6 *servaddr, size_t servaddr_len,
		   int *sockfd);

/**
 * @brief	Initializes an UDP client or server socket.
 * @param   sock_t CLIENT or SERVER
 * @param   addr_str ip address as string
 * @param   ip_t IPv4 or IPv6
 * @param   servaddr struct of type sockaddr_in or sockaddr_in6 
 * @param   servaddr_len length of servaddr  
 * @retval	error code
 */
int sock_init(enum sock_type sock_t, const char *addr_str,
	      enum ip_addr_type ip_t, void *servaddr, size_t servaddr_len,
	      int *sockfd);
#endif
