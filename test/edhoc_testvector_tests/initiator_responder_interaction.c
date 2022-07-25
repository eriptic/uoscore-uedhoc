#include <zephyr.h>
#include <ztest.h>

#include <edhoc.h>

uint8_t I_prk_exporter[32];
uint8_t I_oscore_master_secret[16];
uint8_t I_oscore_master_salt[8];

/* size of stack area used by each thread */
#define STACKSIZE 1024
/* scheduling priority used by each thread */
#define PRIORITY 7
K_THREAD_STACK_DEFINE(thread_initiator_stack_area, STACKSIZE);
static struct k_thread thread_initiator_data;
K_THREAD_STACK_DEFINE(thread_responder_stack_area, STACKSIZE);
static struct k_thread thread_responder_data;

/*semaphores*/
K_SEM_DEFINE(tx_initiator_completed, 0, 1);
K_SEM_DEFINE(tx_responder_completed, 0, 1);

/*message exchange buffer*/
uint8_t msg_exchange_buf[1024];
uint32_t msg_exchange_buf_len = sizeof(msg_exchange_buf);

uint8_t i_tx_buf[1];
uint32_t i_tx_buf_len = sizeof(i_tx_buf);

uint8_t i_rx_buf[1];
uint32_t i_rx_buf_len = sizeof(i_rx_buf);

uint8_t r_tx_buf[1];
uint32_t r_tx_buf_len = sizeof(r_tx_buf);

uint8_t r_rx_buf[1];
uint32_t r_rx_buf_len = sizeof(r_rx_buf);

void semaphore_give(struct k_sem *sem)
{
	k_sem_give(sem);
}

enum err semaphore_take(struct k_sem *sem, uint8_t *data, uint32_t *data_len)
{
	if (k_sem_take(sem, K_MSEC(50)) != 0) {
		PRINT_MSG("Cannot receive a message!\n");
	} else {
		if (msg_exchange_buf_len > *data_len) {
			return buffer_to_small;
		} else {
			memcpy(data, msg_exchange_buf, *data_len);
			*data_len = msg_exchange_buf_len;
		}
	}
	return ok;
}

enum err copy_message(uint8_t *data, uint32_t data_len)
{
	if (data_len > msg_exchange_buf_len) {
		PRINT_MSG("msg_exchange_buf to small");
		return buffer_to_small;
	} else {
		memcpy(msg_exchange_buf, data, data_len);
		msg_exchange_buf_len = data_len;
	}
	return ok;
}

enum err tx_initiator(void *sock, uint8_t *data, uint32_t data_len)
{
	enum err r = copy_message(data, data_len);
	if (r != ok) {
		return r;
	}
	semaphore_give(&tx_initiator_completed);
	return ok;
}

enum err tx_responder(void *sock, uint8_t *data, uint32_t data_len)
{
	enum err r = copy_message(data, data_len);
	if (r != ok) {
		return r;
	}
	semaphore_give(&tx_responder_completed);
	return ok;
}

enum err rx_initiator(void *sock, uint8_t *data, uint32_t *data_len)
{
	return semaphore_take(&tx_responder_completed, data, data_len);
}
enum err rx_responder(void *sock, uint8_t *data, uint32_t *data_len)
{
	return semaphore_take(&tx_initiator_completed, data, data_len);
}

void thread_initiator(void *dummy1, void *dummy2, void *dummy3)
{
	ARG_UNUSED(dummy1);
	ARG_UNUSED(dummy2);
	ARG_UNUSED(dummy3);

	PRINT_MSG("Initiator thread started!\n");

	tx_initiator(NULL, i_tx_buf, i_tx_buf_len);
	PRINT_MSG("Initiator sent msg 1!\n");
	rx_initiator(NULL, i_rx_buf, &i_rx_buf_len);
	PRINT_MSG("Initiator received msg 2!\n");

	tx_initiator(NULL, i_tx_buf, i_tx_buf_len);
	PRINT_MSG("Initiator sent msg 3!\n");
	rx_initiator(NULL, i_rx_buf, &i_rx_buf_len);
	PRINT_MSG("Initiator received msg 4!\n");
}

void thread_responder(void *dummy1, void *dummy2, void *dummy3)
{
	ARG_UNUSED(dummy1);
	ARG_UNUSED(dummy2);
	ARG_UNUSED(dummy3);

	PRINT_MSG("Responder thread started!\n");

	rx_responder(NULL, r_rx_buf, &r_rx_buf_len);
	PRINT_MSG("Responder received msg 1!\n");

	tx_responder(NULL, r_tx_buf, r_tx_buf_len);
	PRINT_MSG("Responder sent msg 2!\n");

	rx_responder(NULL, r_rx_buf, &r_rx_buf_len);
	PRINT_MSG("Responder received msg 3!\n");
	tx_responder(NULL, r_tx_buf, r_tx_buf_len);
	PRINT_MSG("Responder sent msg 4!\n");
}

void test_initiator_responder_interaction(uint8_t vec_num)
{
	PRINT_MSG("start initiator_responder_interaction\n");
	/*initiator*/
	k_thread_create(&thread_initiator_data, thread_initiator_stack_area,
			K_THREAD_STACK_SIZEOF(thread_initiator_stack_area),
			thread_initiator, NULL, NULL, NULL, PRIORITY, 0,
			K_NO_WAIT);

	/*responder*/
	k_thread_create(&thread_responder_data, thread_responder_stack_area,
			K_THREAD_STACK_SIZEOF(thread_responder_stack_area),
			thread_responder, NULL, NULL, NULL, PRIORITY, 0,
			K_NO_WAIT);

	k_thread_start(&thread_initiator_data);
	k_thread_start(&thread_responder_data);

	k_thread_join(&thread_initiator_data, K_FOREVER);

	PRINT_MSG("threads completed\n");
}
