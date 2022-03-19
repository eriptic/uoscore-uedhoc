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

int sock_init(enum sock_type sock_t, const char *addr_str,
	      enum ip_addr_type ip_t, void *servaddr, size_t servaddr_len,
	      int *sockfd)
{
	int r;
	if (ip_t == IPv4) {
		r = ipv4_sock_init(sock_t, addr_str,
				   (struct sockaddr_in *)servaddr, servaddr_len,
				   sockfd);
		if (r < 0)
			return r;
	} else {
		r = ipv6_sock_init(sock_t, addr_str,
				   (struct sockaddr_in6 *)servaddr,
				   servaddr_len, sockfd);
		if (r < 0)
			return r;
	}
	return 0;
}
