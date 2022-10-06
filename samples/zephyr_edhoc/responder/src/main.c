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

#include <zephyr/net/coap.h>

#include "edhoc.h"
#include "sock.h"
#include "edhoc_test_vectors_p256_v16.h"

struct sockaddr_storage client_addr;
socklen_t client_addr_len;

/**
 * @brief	Initializes socket for CoAP server.
 * @param	
 * @retval	error code
 */
static int start_coap_server(int *sockfd)
{
	int err;

	struct sockaddr_in6 servaddr;
	//struct sockaddr_in6 client_addr;
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	const char IPV6_SERVADDR[] = { "2001:db8::1" };
	err = ipv6_sock_init(SOCK_SERVER, IPV6_SERVADDR, &servaddr,
			     sizeof(servaddr), sockfd);
	if (err < 0) {
		printf("error during socket initialization (error code: %d)",
		       err);
		return -1;
	}

	return 0;
}

struct coap_packet cp_req;

enum err tx(void *sock, uint8_t *data, uint32_t data_len)
{
	char buffer[MAXLINE];
	struct coap_packet cp_ack;
	int r;
	const uint8_t COAP_CHANGED = 0b01000100;

	r = coap_ack_init(&cp_ack, &cp_req, buffer, sizeof(buffer),
			  COAP_CHANGED);
	if (r < 0) {
		printf("coap_ack_init failed\n");
		return unexpected_result_from_ext_lib;
	}

	r = coap_packet_append_payload_marker(&cp_ack);
	if (r < 0) {
		printf("coap_packet_append_payload_marker failed\n");
		return unexpected_result_from_ext_lib;
	}

	r = coap_packet_append_payload(&cp_ack, data, data_len);
	if (r < 0) {
		printf("coap_packet_append_payload failed\n");
		return unexpected_result_from_ext_lib;
	}

	PRINT_ARRAY("Sending CoAP message", buffer, cp_ack.offset);

	r = sendto(*((int *)sock), buffer, cp_ack.offset, 0,
		   (struct sockaddr *)&client_addr, client_addr_len);
	if (r < 0) {
		printf("Error: failed to send reply (Code: %d, ErrNo: %d)\n", r,
		       errno);
		return r;
	}

	return ok;
}

enum err rx(void *sock, uint8_t *data, uint32_t *data_len)
{
	int n;
	char buffer[MAXLINE];

	const uint8_t *edhoc_data_p;
	uint16_t edhoc_data_len;

	/* receive */
	client_addr_len = sizeof(client_addr);
	memset(&client_addr, 0, sizeof(client_addr));
	memset(&cp_req, 0, sizeof(cp_req));
	memset(&buffer, 0, sizeof(buffer));

	printf("waiting to receive in rx()\n");
	n = recvfrom(*((int *)sock), (char *)buffer, sizeof(buffer), 0,
		     (struct sockaddr *)&client_addr, &client_addr_len);
	if (n < 0) {
		printf("recv error\n");
	}

	PRINT_ARRAY("received data", buffer, n);

	TRY_EXPECT(coap_packet_parse(&cp_req, buffer, n, NULL, 0), 0);

	edhoc_data_p = coap_packet_get_payload(&cp_req, &edhoc_data_len);

	PRINT_ARRAY("received EDHOC data", edhoc_data_p, edhoc_data_len);

	if (*data_len >= edhoc_data_len) {
		memcpy(data, edhoc_data_p, edhoc_data_len);
		*data_len = edhoc_data_len;
	} else {
		printf("insufficient space in buffer");
		return buffer_to_small;
	}

	return ok;
}

void main(void)
{
	int sockfd;
	uint8_t prk_exporter[32];
	uint8_t oscore_master_secret[16];
	uint8_t oscore_master_salt[8];

	/* edhoc declarations */
	uint8_t PRK_out[PRK_DEFAULT_SIZE];
	uint8_t err_msg[ERR_MSG_DEFAULT_SIZE];
	uint32_t err_msg_len = sizeof(err_msg);
	uint8_t ad_1[AD_DEFAULT_SIZE];
	uint32_t ad_1_len = sizeof(ad_1);
	uint8_t ad_3[AD_DEFAULT_SIZE];
	uint32_t ad_3_len = sizeof(ad_1);

	/* test vector inputs */
	uint16_t cred_num = 1;
	struct other_party_cred cred_i;
	struct edhoc_responder_context c_r;

	uint8_t TEST_VEC_NUM = 2;
	uint8_t vec_num_i = TEST_VEC_NUM - 1;

	start_coap_server(&sockfd);

	c_r.msg4 = true;
	c_r.sock = &sockfd;
	c_r.c_r.ptr = (uint8_t *)test_vectors[vec_num_i].c_r;
	c_r.c_r.len = test_vectors[vec_num_i].c_r_len;
	c_r.suites_r.len = test_vectors[vec_num_i].SUITES_R_len;
	c_r.suites_r.ptr = (uint8_t *)test_vectors[vec_num_i].SUITES_R;
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

	cred_i.id_cred.len = test_vectors[vec_num_i].id_cred_i_len;
	cred_i.id_cred.ptr = (uint8_t *)test_vectors[vec_num_i].id_cred_i;
	cred_i.cred.len = test_vectors[vec_num_i].cred_i_len;
	cred_i.cred.ptr = (uint8_t *)test_vectors[vec_num_i].cred_i;
	cred_i.g.len = test_vectors[vec_num_i].g_i_raw_len;
	cred_i.g.ptr = (uint8_t *)test_vectors[vec_num_i].g_i_raw;
	cred_i.pk.len = test_vectors[vec_num_i].pk_i_raw_len;
	cred_i.pk.ptr = (uint8_t *)test_vectors[vec_num_i].pk_i_raw;
	cred_i.ca.len = test_vectors[vec_num_i].ca_i_len;
	cred_i.ca.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i;
	cred_i.ca_pk.len = test_vectors[vec_num_i].ca_i_pk_len;
	cred_i.ca_pk.ptr = (uint8_t *)test_vectors[vec_num_i].ca_i_pk;

	while (1) {
		edhoc_responder_run(&c_r, &cred_i, cred_num, err_msg,
				    &err_msg_len, (uint8_t *)&ad_1, &ad_1_len,
				    (uint8_t *)&ad_3, &ad_3_len, PRK_out,
				    sizeof(PRK_out), tx, rx);
		PRINT_ARRAY("PRK_out", PRK_out, sizeof(PRK_out));

		prk_out2exporter(SHA_256, PRK_out, sizeof(PRK_out),
				 prk_exporter);
		PRINT_ARRAY("prk_exporter", prk_exporter, sizeof(prk_exporter));

		edhoc_exporter(SHA_256, OSCORE_MASTER_SECRET, prk_exporter,
			       sizeof(prk_exporter), oscore_master_secret,
			       sizeof(oscore_master_secret));
		PRINT_ARRAY("OSCORE Master Secret", oscore_master_secret,
			    sizeof(oscore_master_secret));

		edhoc_exporter(SHA_256, OSCORE_MASTER_SALT, prk_exporter,
			       sizeof(prk_exporter), oscore_master_salt,
			       sizeof(oscore_master_salt));
		PRINT_ARRAY("OSCORE Master Salt", oscore_master_salt,
			    sizeof(oscore_master_salt));
	}

	close(sockfd);
}