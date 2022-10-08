

#ifndef UNIT_TEST_H
#define UNIT_TEST_H

/*when UNIT_TEST is defined all static functions are not static anymore and 
can be used in unit test files.*/
#if UNIT_TEST
#define STATIC

/*the prototypes of all static functions that are used in unit tests*/
enum err inner_outer_option_split(struct o_coap_packet *in_o_coap,
					 struct o_coap_option *e_options,
					 uint8_t *e_options_cnt,
					 uint16_t *e_options_len,
					 struct o_coap_option *U_options,
					 uint8_t *U_options_cnt);

#else
#define STATIC static
#endif

#endif