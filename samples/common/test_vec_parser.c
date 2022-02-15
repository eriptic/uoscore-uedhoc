#include <jsmn.h>
#include <stdio.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include "../../modules/edhoc/edhoc.h"
#include "test_vec_parser.h"
#include "cbor/decode_c_x.h"
#include "cbor/decode_suites_i.h"
#include "../../modules/common/inc/memcpy_s.h"

/**
 * @brief	Checks if json object is a given string
 * @param	json the buffer containing the json string
 * @param	tok the current token which we want to mach
 * @param	s the string that we are expecting
 * @retval	0 if success, else -1
 */
static int jsoneq(const char *json, jsmntok_t *tok, const char *s)
{
	bool type_ok = tok->type == JSMN_STRING;
	bool len_ok = (int)strlen(s) == tok->end - tok->start;
	bool content_eq =
		strncmp(json + tok->start, s, tok->end - tok->start) == 0;

	if (type_ok && len_ok && content_eq) {
		return 0;
	}
	return -1;
}
/**
 * @brief	Transforms a a bystring to an array of bytes
 * @param	str the input string
 * @param	str_len the lenhgt og the string
 * @param	bytes output
 * @retval	0 if success, else -1
 */
static inline int str2bytes(char *str, uint32_t str_len,
			    struct byte_array *bytes)
{
	if (bytes->len < str_len / 2) {
		return -1;
	}
	bytes->len = str_len / 2;

	char *pos = str;
	for (uint32_t i = 0; i < str_len / 2; i++) {
		sscanf(pos, "%2hhx", &bytes->ptr[i]);
		pos += 2;
	}
	return 0;
}

/**
 * @brief	Finds out the range of a test vector inside of the json 
 * 		input file.
 * @param	t pointer to json token array
 * @param	t_len lenhgt of t
 * @param	start_pos the start position is output here
 * @param	end_pos the end position is output here
 * @param	vec_num	the test vector number
 * @retval	0 if success, else -1
 */
static inline int get_test_ver_range(jsmntok_t *t, uint32_t t_len,
				     uint32_t *start_pos, uint32_t *end_pos,
				     uint8_t vec_num)
{
	uint32_t i;
	uint8_t vec_cnt = 0;
	/*skip the very first element*/
	for (i = 1; i < t_len; i++) {
		if (t[i].type == JSMN_OBJECT) {
			vec_cnt++;
			if (vec_cnt == vec_num) {
				/*at i the test vector with vec_num starts*/
				*start_pos = i;
				*end_pos = i + (2 * t[i].size);
				return 0;
			}
		}
	}
	/*there is no vector with this number*/
	return -1;
}

/**
 * @brief	Gets an element with name element_name from the test_vec_buf 	*	       and puts it into the element.
 * @param	test_vec_buf buffer containing all test vectos as a string
 * @param	t pointer to a json token array
 * @param	t_len lenhgt of the array
 * @param	element_name name of the element that value needs tp be 
 * 		extrakted
 * @param	vec_num the test vector number of interest
 * @param	element the output
 * @retval	0 if success, else -1
 */
static int get_element(char *test_vec_buf, jsmntok_t *t, uint32_t t_len,
		       char *element_name, uint8_t vec_num,
		       struct byte_array *element)
{
	uint32_t start_pos = 0, end_pos = 0;
	uint32_t i;

	TRY(get_test_ver_range(t, t_len, &start_pos, &end_pos, vec_num) != 0);

	for (i = start_pos; i < end_pos; i++) {
		if (jsoneq(test_vec_buf, &t[i], element_name) == 0) {
			uint32_t len = t[i + 1].end - t[i + 1].start;
			char *stat_str = test_vec_buf + t[i + 1].start;
			PRINTF("%s (size %d): %.*s\n", element_name, len >> 1,
			       len, stat_str);
			TRY(str2bytes(stat_str, len, element));
			return 0;
		}
	}
	PRINTF("No element called \"%s\" found in test_vector %d\n",
	       element_name, vec_num);
	return 0;
}
/**
 * @brief	Gets suites and decodes it to an uint8_t array.
 * @param	test_vec_buf buffer containing all test vectos as a string
 * @param	t pointer to a json token array
 * @param	t_len lenhgt of the array
 * @param	suite_name name of the suite that value needs tp be 
 * 		extrakted
 * @param	vec_num the test vector number of interest
 * @param	suites_i the output
 * @retval	0 if success, else -1
 */
int get_suites_decode(char *test_vec_buf, jsmntok_t *t, uint32_t t_len,
		      char *suite_name, uint8_t vec_num,
		      struct byte_array *suites_i)
{
	uint8_t tmp_buf[32];
	struct byte_array tmp;
	byte_array_init(tmp_buf, sizeof(tmp_buf), &tmp);
	TRY(get_element(test_vec_buf, t, t_len, suite_name, vec_num, &tmp));

	uint32_t decode_len = 0;
	struct suites_ s;

	TRY_EXPECT(cbor_decode_suites(tmp.ptr, tmp.len, &s, &decode_len), true);

	if (s._suites_choice == _suites_int) {
		*suites_i->ptr = s._suites_int;
		suites_i->len = 1;
		PRINTF("SUITES_I_raw (int): %d\n", *suites_i->ptr);
	} else {
		if (suites_i->len < s._suites__int_int_count) {
			return -1;
		}
		for (uint8_t i = 0; i < s._suites__int_int_count; i++) {
			*(suites_i->ptr + i) = s._suites__int_int[i];
		}
		suites_i->len = s._suites__int_int_count;
		PRINT_ARRAY("SUITES_I_raw", suites_i->ptr, suites_i->len);
	}

	return 0;
}

/**
 * @brief	Gets C_I/C_R and decodes it.
 * @param	test_vec_buf buffer containing all test vectos as a string
 * @param	t pointer to a json token array
 * @param	t_len lenhgt of the array
 * @param	suite_name name of the suite that value needs tp be 
 * 		extrakted
 * @param	vec_num the test vector number of interest
 * @param	c_x_out the output
 * @retval	0 if success, else -1
 */
int get_C_X_decode(uint8_t vec_num, char *test_vec_buf, int r, jsmntok_t *t,
		   uint8_t *cx_buf, char *cx_name, uint32_t cx_buf_len,
		   struct c_x *c_x_out)
{
	/* get c_i or c_x and decode it to int/bstr */
	uint8_t c_x_tmp_buf[32];
	struct byte_array c_x_tmp;
	byte_array_init(c_x_tmp_buf, sizeof(c_x_tmp_buf), &c_x_tmp);
	TRY(get_element(test_vec_buf, t, r, cx_name, vec_num, &c_x_tmp));

	uint32_t decode_len = 0;
	enum err err;
	struct cx_C_X_ cx;

	TRY_EXPECT(cbor_decode_cx_C_X(c_x_tmp.ptr, c_x_tmp.len, &cx,
				      &decode_len),
		   true);

	if (cx._cx_C_X_choice == _cx_C_X_int) {
		c_x_out->type = INT;
		c_x_out->mem.c_x_int = cx._cx_C_X_int;
		PRINTF("C_x_raw (int): %d\n", c_x_out->mem.c_x_int);
	} else {
		c_x_init(c_x_out, cx_buf, cx_buf_len);
		c_x_out->type = BSTR;
		err = _memcpy_s(c_x_out->mem.c_x_bstr.ptr,
				c_x_out->mem.c_x_bstr.len,
				cx._cx_C_X_bstr.value, cx._cx_C_X_bstr.len);
		c_x_out->mem.c_x_bstr.len = cx._cx_C_X_bstr.len;
		if (err != ok) {
			printf("the buffer for C_X is to small");
			return -1;
		}
		PRINT_ARRAY("C_x_raw (bstr):", c_x_out->mem.c_x_bstr.ptr,
			    c_x_out->mem.c_x_bstr.len);
	}
	return 0;
}

int get_OTHER_PARTY_CRED_from_test_vec(enum role other_party_role,
				       struct other_party_cred_bufs *bufs,
				       struct other_party_cred *c,
				       uint8_t vec_num, char *test_vec_buf,
				       uint32_t test_vec_buf_len)
{
	int r;
	jsmn_parser p;
	jsmntok_t t[20000]; /* We expect no more than 20000 tokens */

	jsmn_init(&p);
	r = jsmn_parse(&p, test_vec_buf, test_vec_buf_len, t,
		       sizeof(t) / sizeof(t[0]));
	if (r < 0) {
		printf("Failed to parse JSON: %d\n", r);
		return -1;
	}

	byte_array_init(bufs->id_cred, sizeof(bufs->id_cred), &c->id_cred);
	byte_array_init(bufs->cred, sizeof(bufs->cred), &c->cred);
	byte_array_init(bufs->pk, sizeof(bufs->pk), &c->pk);
	byte_array_init(bufs->g, sizeof(bufs->g), &c->g);
	byte_array_init(bufs->ca, sizeof(bufs->ca), &c->ca);
	byte_array_init(bufs->ca_pk, sizeof(bufs->ca_pk), &c->ca_pk);

	if (other_party_role == INITIATOR) {
		PRINT_MSG(
			"\nReading the parametes of the other party (initiator)...\n");
		get_element(test_vec_buf, t, r, "id_cred_i", vec_num,
			    &c->id_cred);
		get_element(test_vec_buf, t, r, "g_i_raw", vec_num, &c->g);
		get_element(test_vec_buf, t, r, "pk_i_raw", vec_num, &c->pk);
		get_element(test_vec_buf, t, r, "cred_i", vec_num, &c->cred);

	} else {
		PRINT_MSG(
			"\nReading the parametes of the other party (responder)...\n");
		get_element(test_vec_buf, t, r, "id_cred_r", vec_num,
			    &c->id_cred);
		get_element(test_vec_buf, t, r, "cred_r", vec_num, &c->cred);
		get_element(test_vec_buf, t, r, "g_r_raw", vec_num, &c->g);
		get_element(test_vec_buf, t, r, "pk_r_raw", vec_num, &c->pk);
	}

	get_element(test_vec_buf, t, r, "ca", vec_num, &c->ca);
	get_element(test_vec_buf, t, r, "ca_pk", vec_num, &c->ca_pk);

	return 0;
}

int get_EDHOC_INITIATOR_CONTEXT_from_test_vec(
	struct edhoc_initiator_context_bufs *bufs,
	struct edhoc_initiator_context *c, uint8_t vec_num, char *test_vec_buf,
	uint32_t test_vec_buf_len)
{
	PRINT_MSG("\nReading the parametes of the initiator...\n");
	int r;
	jsmn_parser p;
	jsmntok_t t[20000]; /* We expect no more than 20000 tokens */
	uint8_t method_buf[1];
	struct byte_array method;

	jsmn_init(&p);
	r = jsmn_parse(&p, test_vec_buf, test_vec_buf_len, t,
		       sizeof(t) / sizeof(t[0]));
	if (r < 0) {
		printf("Failed to parse JSON: %d\n", r);
		return -1;
	}

	/*use message 4 in all tests*/
	c->msg4 = true;

	byte_array_init(method_buf, sizeof(method_buf), &method);
	byte_array_init(bufs->suites_i, sizeof(bufs->suites_i), &c->suites_i);
	byte_array_init(bufs->ead_1, sizeof(bufs->ead_1), &c->ead_1);
	byte_array_init(bufs->ead_3, sizeof(bufs->ead_3), &c->ead_3);
	byte_array_init(bufs->id_cred_i, sizeof(bufs->id_cred_i),
			&c->id_cred_i);
	byte_array_init(bufs->cred_i, sizeof(bufs->cred_i), &c->cred_i);
	byte_array_init(bufs->g_x, sizeof(bufs->g_x), &c->g_x);
	byte_array_init(bufs->x, sizeof(bufs->x), &c->x);
	byte_array_init(bufs->g_i, sizeof(bufs->g_i), &c->g_i);
	byte_array_init(bufs->i, sizeof(bufs->i), &c->i);
	byte_array_init(bufs->pk_i, sizeof(bufs->pk_i), &c->pk_i);
	byte_array_init(bufs->sk_i, sizeof(bufs->sk_i), &c->sk_i);

	get_element(test_vec_buf, t, r, "method", vec_num, &method);
	c->method = method_buf[0];
	get_element(test_vec_buf, t, r, "ead_1", vec_num, &c->ead_1);
	get_element(test_vec_buf, t, r, "ead_3", vec_num, &c->ead_3);
	get_element(test_vec_buf, t, r, "id_cred_i", vec_num, &c->id_cred_i);
	get_element(test_vec_buf, t, r, "cred_i", vec_num, &c->cred_i);
	get_element(test_vec_buf, t, r, "g_x_raw", vec_num, &c->g_x);
	get_element(test_vec_buf, t, r, "x_raw", vec_num, &c->x);
	get_element(test_vec_buf, t, r, "g_i_raw", vec_num, &c->g_i);
	get_element(test_vec_buf, t, r, "i_raw", vec_num, &c->i);
	get_element(test_vec_buf, t, r, "pk_i_raw", vec_num, &c->pk_i);
	get_element(test_vec_buf, t, r, "sk_i_raw", vec_num, &c->sk_i);

	get_suites_decode(test_vec_buf, t, r, "suites_i", vec_num,
			  &c->suites_i);
	return get_C_X_decode(vec_num, test_vec_buf, r, t, bufs->c_i, "c_i",
			      sizeof(bufs->c_i), &c->c_i);
}

int get_EDHOC_RESPONDER_CONTEXT_from_test_vec(
	struct edhoc_responder_context_bufs *bufs,
	struct edhoc_responder_context *c, uint8_t vec_num, char *test_vec_buf,
	uint32_t test_vec_buf_len)
{
	PRINT_MSG("\nReading the parametes of the responder...\n");
	int r;
	jsmn_parser p;
	jsmntok_t t[20000]; /* We expect no more than 20000 tokens */

	jsmn_init(&p);
	r = jsmn_parse(&p, test_vec_buf, test_vec_buf_len, t,
		       sizeof(t) / sizeof(t[0]));
	if (r < 0) {
		printf("Failed to parse JSON: %d\n", r);
		return -1;
	}

	/*use message 4 in all tests*/
	c->msg4 = true;

	byte_array_init(bufs->suites_r, sizeof(bufs->suites_r), &c->suites_r);
	byte_array_init(bufs->g_y, sizeof(bufs->g_y), &c->g_y);
	byte_array_init(bufs->y, sizeof(bufs->y), &c->y);
	byte_array_init(bufs->g_r, sizeof(bufs->g_r), &c->g_r);
	byte_array_init(bufs->r, sizeof(bufs->r), &c->r);
	byte_array_init(bufs->ead_2, sizeof(bufs->ead_2), &c->ead_2);
	byte_array_init(bufs->ead_4, sizeof(bufs->ead_4), &c->ead_4);
	byte_array_init(bufs->id_cred_r, sizeof(bufs->id_cred_r),
			&c->id_cred_r);
	byte_array_init(bufs->cred_r, sizeof(bufs->cred_r), &c->cred_r);
	byte_array_init(bufs->sk_r, sizeof(bufs->sk_r), &c->sk_r);
	byte_array_init(bufs->pk_r, sizeof(bufs->pk_r), &c->pk_r);

	get_element(test_vec_buf, t, r, "suites_r", vec_num, &c->suites_r);
	get_element(test_vec_buf, t, r, "ead_2", vec_num, &c->ead_2);
	get_element(test_vec_buf, t, r, "ead_4", vec_num, &c->ead_4);
	get_element(test_vec_buf, t, r, "id_cred_r", vec_num, &c->id_cred_r);
	get_element(test_vec_buf, t, r, "cred_r", vec_num, &c->cred_r);
	get_element(test_vec_buf, t, r, "g_y_raw", vec_num, &c->g_y);
	get_element(test_vec_buf, t, r, "y_raw", vec_num, &c->y);
	get_element(test_vec_buf, t, r, "g_r_raw", vec_num, &c->g_r);
	get_element(test_vec_buf, t, r, "r_raw", vec_num, &c->r);
	get_element(test_vec_buf, t, r, "sk_r_raw", vec_num, &c->sk_r);
	get_element(test_vec_buf, t, r, "pk_r_raw", vec_num, &c->pk_r);

	get_suites_decode(test_vec_buf, t, r, "suites_r", vec_num,
			  &c->suites_r);
	return get_C_X_decode(vec_num, test_vec_buf, r, t, bufs->c_r, "c_r",
			      sizeof(bufs->c_r), &c->c_r);
}

int get_MESSAGES_from_test_vec(struct messages_bufs *bufs, struct messages *m,
			       uint8_t vec_num, char *test_vec_buf,
			       uint32_t test_vec_buf_len)
{
	int r;
	jsmn_parser p;
	jsmntok_t t[20000]; /* We expect no more than 20000 tokens */

	jsmn_init(&p);
	r = jsmn_parse(&p, test_vec_buf, test_vec_buf_len, t,
		       sizeof(t) / sizeof(t[0]));
	if (r < 0) {
		printf("Failed to parse JSON: %d\n", r);
		return -1;
	}

	byte_array_init(bufs->m1, sizeof(bufs->m1), &m->m1);
	byte_array_init(bufs->m2, sizeof(bufs->m2), &m->m2);
	byte_array_init(bufs->m3, sizeof(bufs->m2), &m->m3);
	byte_array_init(bufs->m4, sizeof(bufs->m4), &m->m4);

	get_element(test_vec_buf, t, r, "message_1", vec_num, &m->m1);
	get_element(test_vec_buf, t, r, "message_2", vec_num, &m->m2);
	get_element(test_vec_buf, t, r, "message_3", vec_num, &m->m3);
	get_element(test_vec_buf, t, r, "message_4", vec_num, &m->m4);

	return 0;
}

int get_RESULTS_from_test_vec(struct results_bufs *bufs, struct results *m,
			      uint8_t vec_num, char *test_vec_buf,
			      uint32_t test_vec_buf_len)
{
	int r;
	jsmn_parser p;
	jsmntok_t t[20000]; /* We expect no more than 20000 tokens */

	jsmn_init(&p);
	r = jsmn_parse(&p, test_vec_buf, test_vec_buf_len, t,
		       sizeof(t) / sizeof(t[0]));
	if (r < 0) {
		printf("Failed to parse JSON: %d\n", r);
		return -1;
	}

	byte_array_init(bufs->prk_4x3m, sizeof(bufs->prk_4x3m), &m->prk_4x3m);
	byte_array_init(bufs->th4, sizeof(bufs->th4), &m->th4);
	byte_array_init(bufs->oscore_master_salt,
			sizeof(bufs->oscore_master_salt),
			&m->oscore_master_salt);
	byte_array_init(bufs->oscore_master_secret,
			sizeof(bufs->oscore_master_secret),
			&m->oscore_master_secret);

	get_element(test_vec_buf, t, r, "prk_4x3m_raw", vec_num, &m->prk_4x3m);
	get_element(test_vec_buf, t, r, "th_4_raw", vec_num, &m->th4);
	get_element(test_vec_buf, t, r, "oscore_salt_raw", vec_num,
		    &m->oscore_master_salt);
	get_element(test_vec_buf, t, r, "oscore_secret_raw", vec_num,
		    &m->oscore_master_secret);

	return 0;
}

int read_test_vectors(char *filename, char *test_vec_buf, uint32_t *len)
{
	long length;
	PRINTF("Opening file: %s\n", filename);

	FILE *f = fopen(filename, "rb");

	if (f == 0) {
		printf("cannot open file\n");
		return -1;
	}

	fseek(f, 0, SEEK_END);
	length = ftell(f);
	fseek(f, 0, SEEK_SET);
	if (*len < length) {
		printf("Your test_vec_buf is to small! The test_vec_buf has size of %d bytes, but the you try to red %ld bytes\n",
		       *len, length);
		return -1;
	}
	*len = length;
	if (test_vec_buf) {
		if (0 == fread(test_vec_buf, 1, length, f)) {
			return -1;
		}
	}
	fclose(f);

	return 0;
}