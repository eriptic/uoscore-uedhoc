/*
   Licensed under the Apache License, Version 2.0 <LICENSE-APACHE or
   http://www.apache.org/licenses/LICENSE-2.0> or the MIT license
   <LICENSE-MIT or http://opensource.org/licenses/MIT>, at your
   option. This file may not be copied, modified, or distributed
   except according to those terms.
*/

#include <string.h>

#include "common/memcpy_s.h"
#include "common/print_util.h"
#include "common/oscore_edhoc_error.h"

#include "edhoc/correlation.h"

/*
 * Case: client uses CoAP token for correlation and server uses connection 
 * identifier (C_R) for correlation
 * 
 * client_initiator                         server_responder 
 * tx()             ---0xf5||msg1-->        rx()
 * rx()             <------msg2-----        tx() 
 * tx()             ---C_R||msg3--->        rx()
 * rx()             <------msg4-----        tx() 
 * 
 * 
 * 
 * 
 *  
 * Case: both client and server use connection identifiers to correlate
 *
 * client_initiator                         server_responder 
 * tx()             ---0xf5||msg1-->        rx()
 * rx()             <---C_I||msg2---        tx() 
 * tx()             ---C_R||msg3--->        rx()
 * rx()             <---C_I||msg4---        tx() 
 */

/**
 * @brief           Concatenates two byte strings
 * 
 * @param msg1      first string
 * @param msg1_len  lenhgt of first string
 * @param msg2      second string
 * @param msg2_len  lenhgt of second string
 * @param out       the concatinated string
 * @param out_len   lenhgt of the concatinated string
 * @return          enum err 
 */
static enum err glue(uint8_t *msg1, uint32_t msg1_len, uint8_t *msg2,
		     uint32_t msg2_len, uint8_t *out, uint32_t *out_len)
{
	TRY(_memcpy_s(out, *out_len, msg1, msg1_len));
	TRY(_memcpy_s(out + msg1_len, *out_len - msg1_len, msg2, msg2_len));
	*out_len = msg1_len + msg2_len;
	return ok;
}

/**
 * @brief   sends data over the wire and if the own correlation is 
 *          accomplished through a corralator on the transport layer,
 *          e.g., a CoAP tocken the correlator (e.g. the tocken) is saved.
 * 
 * @param state     a EDHOC state variable 
 * @param own_corr  the own correlation type -> can be TRANSPORT or C_x
 * @param sock      a socket to be used for sending    
 * @param data      data to be send
 * @param data_len  lenhgt of the data to be send
 * @param tx        call back function for sending data
 * @return          enum err 
 */
static enum err tx_get_transport_corr(
	void *state, enum correlator_type own_corr, void *sock, uint8_t *data,
	uint32_t data_len,
	enum err (*tx)(void *sock, uint8_t *data, uint32_t data_len,
		       uint8_t *corr, uint32_t *corr_len))
{
	if (own_corr == TRANSPORT) {
		TRY(tx(sock, data, data_len,
		       ((struct state_i *)state)->own_corr,
		       &((struct state_i *)state)->own_corr_len));
	} else {
		TRY(tx(sock, data, data_len, NULL, NULL));
	}
}

enum err tx_correlate(uint8_t data, uint32_t data_len, enum role role,
		      void *state, enum correlator_type own_corr,
		      enum correlator_type other_party_corr, void *sock,
		      enum err (*tx)(void *sock, uint8_t *data,
				     uint32_t data_len, uint8_t *corr,
				     uint32_t *corr_len))
{
	switch (role) {
	case INITIATOR_CLIENT:

		if (other_party_corr == C_x) {
			uint8_t msg[MSG_DEFAULT_SIZE];
			uint32_t msg_len;

			if (((struct state_i *)state)->cr_set) {
				TRY(glue(((struct state_i *)state)
						 ->other_party_corr,
					 ((struct state_i *)state)
						 ->other_party_corr_len,
					 data, data_len, msg, &msg_len));
			} else {
				uint8_t cbor_true = CBOR_TRUE;
				TRY(glue(&cbor_true, 1, data, data_len, msg,
					 &msg_len));
			}
			/*send and save a correlator value for correlating the own 
            messages if the transport shall provide such value*/
			TRY(tx_get_transport_corr(state, own_corr, sock, msg,
						  msg_len, tx));

		} else {
			/*send without prepending C_R/CBOR_TRUE, since somthing 
            equivalent will perepended on the ransport layer. 
            Save a correlator value for correlating the own messages 
            if the transport shall provide such value*/
			TRY(tx_get_transport_corr(state, own_corr, sock, data,
						  data_len, tx));
		}
		break;

	case RESPONDER_SERVER:
		uint8_t msg[MSG_DEFAULT_SIZE];
		uint32_t msg_len;

		if (other_party_corr == C_x) {
			TRY(glue(((struct state_r *)state)->other_party_corr,
				 ((struct state_r *)state)->other_party_corr_len,
				 data, data_len, msg, &msg_len));
			TRY(tx_get_transport_corr(state, own_corr, sock, msg,
						  msg_len, tx));
		} else {
			TRY(tx_get_transport_corr(state, own_corr, sock, data,
						  data_len, tx));
		}
		break;

		/*not implemented yet*/
	case INITIATOR_SERVER:
		/* code */
		break;

	case RESPONDER_CLIENT:
		/* code */
		break;
	}
}

static enum err new_state(void *state, uint32_t number_of_states, void *out)
{
}

/**
 * @brief 					Get the edhoc state
 * 
 * @param state 			a pointer to an array of states 
 * 							(not all slots may be used)
 * @param number_of_states  the lenhgt of the state array 
 * 							(the maximal number of parallel states) 
 * @param r 				the role can be:
 * 							INITIATOR_CLIENT
 * 							INITIATOR_SERVER
 * 							RESPONDER_CLIENT
 * 							RESPONDER_SERVER
 * 
 * @param corr 				A correlator received form the transport layer or 
 * 							a prepended connection identifier (C_x).
 * @param corr_len 			Length of the correlator
 * @param out 				The state to be used for the subsequent operations
 * @return 					enum err 
 */
static enum err get_edhoc_state(void *state, uint32_t number_of_states,
				enum role r, uint8_t *corr, uint32_t corr_len,
				void *out)
{
	if (r == INITIATOR_CLIENT || r == INITIATOR_SERVER) {
		for (uint32_t i = 0; i < number_of_states; i++) {
			if (corr_len ==
			    ((struct state_r *)state)[i].own_corr_len) {
				if (0 == memcmp(*((struct state_r *)state)[i]
							 .own_corr,
						corr, corr_len)) {
					PRINTF("EDHOC state found at slot %d!\n",
					       i);
					out = &state[i];
					return ok;
				}
			}
		}
	} else if (r == RESPONDER_CLIENT || r == RESPONDER_SERVER) {
		if (corr_len == 1 && corr[0] == CBOR_TRUE) {
			/*we create a new state*/
		}

		for (uint32_t i = 0; i < number_of_states; i++) {
			if (corr_len ==
			    ((struct state_r *)state)[i].own_corr_len) {
				if (0 == memcmp(*((struct state_r *)state)[i]
							 .own_corr,
						corr, corr_len)) {
					PRINTF("EDHOC state found at slot %d!\n",
					       i);
					out = &state[i];
					return ok;
				}
			}
		}
	}

	return no_such_state;
}

enum err rx_correlate(uint8_t *data, uint32_t *data_len, enum role role,
		      void *state, enum correlator_type own_corr,
		      enum correlator_type other_party_corr, void *sock,
		      enum err (*rx)(void *sock, uint8_t *data,
				     uint32_t data_len, uint8_t *corr,
				     uint32_t *corr_len))
{
	uint8_t msg[MSG_DEFAULT_SIZE];
	uint32_t msg_len;
	uint8_t transpot_layer_corr[CORR_DEFAULT_SIZE];
	uint32_t transpot_layer_corr_len;

	TRY(rx(sock, msg, &msg_len, transpot_layer_corr,
	       transpot_layer_corr_len));

	switch (role) {
	case INITIATOR_CLIENT:

		if (own_corr == C_x) {
		} else {
		}
		break;

	case RESPONDER_SERVER:

		break;

		/*not implemented yet*/
	case INITIATOR_SERVER:
	case RESPONDER_CLIENT:
		return not_implemented;
		break;
	}
}